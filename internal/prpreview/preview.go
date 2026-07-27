package prpreview

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
)

// Preview is the whole reviewable pre-PR: what changes, against which public
// base, with the warnings a human must see before authorizing.
type Preview struct {
	Files         []FileDiff
	BaseCommitSHA string
	// TotalAdded/TotalRemoved summarize the whole pre-PR.
	TotalAdded, TotalRemoved int
	// Warnings render ABOVE the file list and the PR text. A safety signal
	// below the fold is not a safety signal.
	Warnings []string
}

// BaseContent supplies a path's content from the public base. It returns
// (nil, false, nil) for a path the base does not have.
type BaseContent func(path string) ([]byte, bool, error)

// Build assembles the reviewable diff for a rebased pre-PR.
//
// The file list is derived from the packet's own entries, so it cannot disagree
// with what publishes. Order is by PATH, matching how GitHub sorts a pull
// request's Files-changed tab: the preview's job is to look like the PR it
// becomes, so sensitive paths are MARKED in place rather than reordered.
func Build(packet commitpacket.Packet, baseCommitSHA string, base BaseContent, baseSHAByPath map[string]string, privateIdentities []attribution.Identity) (Preview, error) {
	if base == nil {
		return Preview{}, errors.New("preview requires base content")
	}
	preview := Preview{BaseCommitSHA: baseCommitSHA}
	blobBySHA := make(map[string][]byte, len(packet.Blobs))
	for _, blob := range packet.Blobs {
		content, err := base64.StdEncoding.DecodeString(blob.Content)
		if err != nil {
			return Preview{}, errors.New("packet blob content is not valid base64")
		}
		blobBySHA[blob.SHA] = content
	}

	// publishedText holds the content that will become public, per path, so the
	// identity scan runs over every changed file regardless of whether its diff
	// body was truncated for display.
	publishedText := make(map[string][]byte)

	for _, entry := range packet.Tree.Entries {
		switch {
		case entry.Delete:
			prior, _, err := base(entry.Path)
			if err != nil {
				return Preview{}, err
			}
			preview.Files = append(preview.Files, DiffFile(entry.Path, prior, nil, ChangeDelete))
		case entry.Type == "commit" || entry.Mode == submoduleTreeMode:
			preview.Files = append(preview.Files, DiffSubmodule(entry.Path, baseSHAByPath[entry.Path], entry.SHA))
		default:
			prior, existed, err := base(entry.Path)
			if err != nil {
				return Preview{}, err
			}
			proposed, carried := blobBySHA[entry.SHA]
			if !carried {
				// The rebase drops a blob the public repo already holds — a
				// mode-only change. Content is unchanged, so the diff is empty
				// and only the entry's mode differs.
				proposed = prior
			}
			kind := ChangeAdd
			if existed {
				kind = ChangeModify
			}
			publishedText[entry.Path] = proposed
			preview.Files = append(preview.Files, DiffFile(entry.Path, prior, proposed, kind))
		}
	}

	sort.Slice(preview.Files, func(i, j int) bool { return preview.Files[i].Path < preview.Files[j].Path })
	for _, file := range preview.Files {
		preview.TotalAdded += file.Added
		preview.TotalRemoved += file.Removed
	}
	preview.Warnings = buildWarnings(preview.Files, publishedText, packet, privateIdentities)
	return preview, nil
}

// buildWarnings inspects EVERY changed file, including any whose diff body was
// omitted for size. A cap on what is rendered must never become a cap on what
// is checked.
func buildWarnings(files []FileDiff, publishedText map[string][]byte, packet commitpacket.Packet, identities []attribution.Identity) []string {
	warnings := make([]string, 0, 3)

	sensitive := make([]string, 0)
	for _, file := range files {
		if file.Sensitive {
			sensitive = append(sensitive, file.Path)
		}
	}
	if len(sensitive) > 0 {
		warnings = append(warnings, "Touches governance-sensitive paths: "+summarizePaths(sensitive))
	}

	if len(identities) > 0 {
		leaking := make([]string, 0)
		for _, file := range files {
			content, present := publishedText[file.Path]
			if !present {
				continue
			}
			if attribution.Contains(string(content), identities) {
				leaking = append(leaking, file.Path)
			}
		}
		if attribution.Contains(packet.Commit.Message, identities) {
			leaking = append(leaking, "(commit message)")
		}
		if identityInSignature(packet, identities) {
			leaking = append(leaking, "(commit author/committer)")
		}
		if len(leaking) > 0 {
			warnings = append(warnings, "Private identifiers would publish in: "+summarizePaths(leaking))
		}
	}
	return warnings
}

// identityInSignature checks the commit's own author and committer fields. They
// publish with the commit and are not part of any file's content, so a
// content-only scan would miss them entirely.
func identityInSignature(packet commitpacket.Packet, identities []attribution.Identity) bool {
	for _, signature := range []commitpacket.Signature{packet.Commit.Author, packet.Commit.Committer} {
		if attribution.Contains(signature.Name+" "+signature.Email, identities) {
			return true
		}
	}
	return false
}

func summarizePaths(paths []string) string {
	if len(paths) <= 4 {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(paths[:4], ", "), len(paths)-4)
}
