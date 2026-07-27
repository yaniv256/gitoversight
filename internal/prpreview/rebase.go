// Package prpreview turns a submitted shape into a pre-PR: the cross-repository
// diff between a public repository's current HEAD (the base) and the shape an
// agent prepared in a private repository (the target).
//
// A pre-PR's two legs live in different repositories, which is what makes it the
// gate on moving work from private to public. Everything here exists to keep
// those legs honest: the base is resolved by the broker from policy, never named
// by the submitting agent, and the reviewed file set is DERIVED from comparing
// the two trees rather than declared alongside them.
package prpreview

import (
	"errors"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
	"github.com/yaniv256/gitoversight.dev/internal/githubapp"
)

// submoduleTreeMode is git's gitlink mode. A submodule entry names a commit in
// the submodule's own repository and carries no blob.
const submoduleTreeMode = "160000"

// Rebased is a shape packet re-expressed against a public base: the entries that
// actually change, the blobs those entries need, and the file manifest derived
// from them.
type Rebased struct {
	// Tree entries relative to BaseTreeSHA — writes and deletes only.
	Entries []commitpacket.TreeEntry
	// Blobs carries content for every non-delete entry whose object the public
	// repository does not already have.
	Blobs []commitpacket.Blob
	// BaseTreeSHA is the public repository's tree at BaseCommitSHA. Empty when
	// the public repository has no commits yet (a root-commit publication).
	BaseTreeSHA string
	// BaseCommitSHA is the public HEAD the diff was taken against.
	BaseCommitSHA string
	// Manifest lists the paths that publish, in path order. Derived, never
	// supplied: it is exactly the non-delete entry paths.
	Manifest []string
	// Deletions lists paths present in the base and absent from the shape.
	Deletions []string
}

// BaseEntry is one path in the public base tree.
type BaseEntry = githubapp.TreeEntry

// Rebase computes the pre-PR delta between a public base tree and a submitted
// shape.
//
// shapeEntries must describe the COMPLETE tree of the proposed state (every
// path, not a delta), because a path that the shape omits and the base contains
// is a deletion — and that is indistinguishable from "unchanged" if the shape is
// itself a delta. This is why the CLI sends a full-tree shape packet.
//
// shapeBlobs supplies content for the shape's entries; a shape entry whose blob
// is absent is an error rather than a skipped file, since a silently dropped
// path would publish nothing while the manifest claimed it published.
func Rebase(baseEntries []BaseEntry, baseTreeSHA, baseCommitSHA string, shapeEntries []commitpacket.TreeEntry, shapeBlobs []commitpacket.Blob) (Rebased, error) {
	if len(shapeEntries) == 0 {
		return Rebased{}, errors.New("shape carries no entries")
	}
	blobBySHA := make(map[string]commitpacket.Blob, len(shapeBlobs))
	for _, blob := range shapeBlobs {
		blobBySHA[blob.SHA] = blob
	}
	baseBySHA := make(map[string]BaseEntry, len(baseEntries))
	for _, entry := range baseEntries {
		if entry.Path == "" {
			return Rebased{}, errors.New("base tree contains an entry with no path")
		}
		baseBySHA[entry.Path] = entry
	}

	shapePaths := make(map[string]struct{}, len(shapeEntries))
	writes := make([]commitpacket.TreeEntry, 0, len(shapeEntries))
	manifest := make([]string, 0, len(shapeEntries))
	needed := make(map[string]struct{})

	for _, entry := range shapeEntries {
		if entry.Delete {
			return Rebased{}, errors.New("shape must describe a complete tree, not deletions")
		}
		if entry.Path == "" || entry.SHA == "" {
			return Rebased{}, errors.New("shape entry is missing a path or hash")
		}
		if _, duplicated := shapePaths[entry.Path]; duplicated {
			return Rebased{}, errors.New("shape entry path is duplicated")
		}
		shapePaths[entry.Path] = struct{}{}

		base, inBase := baseBySHA[entry.Path]
		// An identical path is not part of the change. Mode is compared too: a
		// file that gains the executable bit changes the tree even though its
		// content hash is unchanged.
		if inBase && base.SHA == entry.SHA && base.Mode == entry.Mode {
			continue
		}
		writes = append(writes, entry)
		manifest = append(manifest, entry.Path)
		// A submodule pointer is resolved by GitHub from the SHA; there is no
		// blob to carry. Everything else needs its content uploaded unless the
		// public repository already holds that exact object.
		if entry.Mode == submoduleTreeMode || entry.Type == "commit" {
			continue
		}
		if inBase && base.SHA == entry.SHA {
			continue
		}
		blob, present := blobBySHA[entry.SHA]
		if !present {
			return Rebased{}, errors.New("shape entry references content the submission did not carry")
		}
		needed[blob.SHA] = struct{}{}
	}

	deletions := make([]commitpacket.TreeEntry, 0)
	deletedPaths := make([]string, 0)
	for _, entry := range baseEntries {
		if _, kept := shapePaths[entry.Path]; kept {
			continue
		}
		deleteType := entry.Type
		if deleteType == "" {
			deleteType = "blob"
		}
		deletions = append(deletions, commitpacket.TreeEntry{Path: entry.Path, Mode: entry.Mode, Type: deleteType, Delete: true})
		deletedPaths = append(deletedPaths, entry.Path)
	}

	if len(writes) == 0 && len(deletions) == 0 {
		return Rebased{}, errors.New("the proposed shape already matches the public repository")
	}

	blobs := make([]commitpacket.Blob, 0, len(needed))
	for _, blob := range shapeBlobs {
		if _, wanted := needed[blob.SHA]; wanted {
			blobs = append(blobs, blob)
			delete(needed, blob.SHA)
		}
	}

	// Deletions precede writes so a path replaced by a differently-typed entry
	// is removed before it is re-added, matching the ordering the existing
	// packet builder produced.
	entries := append(deletions, writes...)
	sort.Strings(manifest)
	sort.Strings(deletedPaths)
	return Rebased{
		Entries:       entries,
		Blobs:         blobs,
		BaseTreeSHA:   baseTreeSHA,
		BaseCommitSHA: baseCommitSHA,
		Manifest:      manifest,
		Deletions:     deletedPaths,
	}, nil
}

// SensitivePath reports whether a path is one a reviewer should be warned about
// before authorizing publication. It annotates; it never reorders (KTD10 — the
// file list tracks GitHub's path order so the preview stays authentic).
func SensitivePath(path string) bool {
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, ".github/workflows/"):
		return true
	case strings.HasPrefix(lower, "policy/"), strings.Contains(lower, "/policy/"):
		return true
	case strings.HasSuffix(lower, ".env"), strings.Contains(lower, ".env."):
		return true
	case strings.Contains(lower, "credential"), strings.Contains(lower, "secret"):
		return true
	case lower == ".gitmodules":
		return true
	}
	return false
}
