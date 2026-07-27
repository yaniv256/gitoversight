package commitpacket

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Packet bounds. Each is labelled with WHERE IT COMES FROM, because most of
// them come from us rather than from GitHub, and a constant that looks like an
// external limit when it is really a chosen margin is a lie the next reader
// will build on.
//
// Audited 2026-07-26 against GitHub's published documentation. The result was
// mostly negative, and the negative result is the useful part:
//
//   - GitHub documents NO maximum blob size for POST /git/blobs. The widely
//     repeated "100 MB blob limit" appears in the docs only under *Get* a blob,
//     not *Create* — it describes retrieval and is misattributed constantly.
//   - GitHub documents NO maximum REST request body size.
//   - GitHub documents NO tree-entry limit for POST /git/trees. The published
//     100,000-entry / 7 MB figure governs the RECURSIVE READ path and its
//     `truncated` flag, not writes.
//   - What IS documented: a single object is "enforced at 100MB"
//     (repository-limits), and a single push is capped at 2 GiB. Neither page
//     states whether it binds Git Data API writes.
//
// So these are not external limits and must not be described as such. They are
// deliberate margins protecting a broker that decodes untrusted JSON into
// memory, sized well under any documented ceiling. Raising one is a policy
// decision, not a bug fix — but it is a decision someone is allowed to make,
// which is exactly what the old bare numbers concealed.
const (
	// MaxBlobs, MaxTreeEntries, MaxPathBytes, MaxTreePathBytes: OURS.
	// Structural ceilings that keep one request from allocating unboundedly.
	// MaxPathBytes matches the conventional filesystem path maximum; the rest
	// are round numbers chosen as margins, comfortably above real trees (this
	// repository publishes ~300 files) and far below anything GitHub rejects.
	MaxBlobs         = 1000
	MaxTreeEntries   = 5000
	MaxPathBytes     = 4096
	MaxTreePathBytes = 1 << 20

	// MaxBlobBytes: OURS. Ten binary megabytes per file. GitHub's documented
	// object ceiling is 100MB and its warning threshold 50 MiB, so this sits an
	// order of magnitude inside both. A repository needing larger single files
	// wants Git LFS, which this path does not implement.
	MaxBlobBytes = 10 << 20

	// MaxTotalBytes: OURS, and the one bound with operational history. At 25
	// MiB it is the real constraint agents hit first when publishing
	// large-asset repositories — recorded as such during the 2026-07-21
	// object-push work, where it was the only genuine limitation found after a
	// missing-capability theory turned out to be wrong.
	MaxTotalBytes = 25 << 20

	// MaxPayloadBytes and MaxRequestBodyBytes: OURS, derived from
	// MaxTotalBytes rather than chosen independently. Base64 inflates content
	// by 4/3, so the JSON payload carrying 25 MiB of blobs is ~33.3 MiB before
	// structural overhead; 38 MiB covers that with room for the tree and commit
	// fields, and 42 MiB leaves headroom for headers and framing above it.
	// packet_test.go asserts this relationship holds, so changing MaxTotalBytes
	// without changing these fails the test rather than silently truncating a
	// valid packet at the HTTP layer.
	MaxPayloadBytes     = 38 << 20
	MaxRequestBodyBytes = 42 << 20
)

type Packet struct {
	Blobs  []Blob `json:"blobs"`
	Tree   Tree   `json:"tree"`
	Commit Commit `json:"commit"`
}

type Blob struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type Tree struct {
	SHA      string      `json:"sha"`
	BaseTree string      `json:"base_tree,omitempty"`
	Entries  []TreeEntry `json:"entries"`
}

type TreeEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Type   string `json:"type"`
	SHA    string `json:"sha,omitempty"`
	Delete bool   `json:"delete,omitempty"`
}

type Commit struct {
	SHA       string    `json:"sha"`
	Message   string    `json:"message"`
	Tree      string    `json:"tree"`
	Parents   []string  `json:"parents"`
	Author    Signature `json:"author"`
	Committer Signature `json:"committer"`
}

type Signature struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

func Decode(payload map[string]any) (Packet, bool, error) {
	raw, exists := payload["object_package"]
	if !exists {
		return Packet{}, false, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return Packet{}, true, errors.New("object package is not JSON")
	}
	var packet Packet
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&packet); err != nil {
		return Packet{}, true, fmt.Errorf("object package is invalid: %w", err)
	}
	return packet, true, packet.Validate()
}

func (p Packet) Validate() error {
	delta := p.Tree.BaseTree != ""
	// A non-delta package may legitimately be EMPTY: a shape describing a tree
	// with no tracked files (every path removed) is a valid proposal, and the
	// commit's own tree SHA still pins it — emptyTreeSHA is git's well-known
	// hash for that tree, so an empty entry set cannot be forged into meaning
	// anything else.
	emptyShape := !delta && len(p.Tree.Entries) == 0 && len(p.Blobs) == 0 && p.Tree.SHA == emptyTreeSHA
	if len(p.Blobs) > MaxBlobs || len(p.Tree.Entries) > MaxTreeEntries || !validSHA(p.Tree.SHA) || (delta && !validSHA(p.Tree.BaseTree)) || (!delta && !emptyShape && (len(p.Blobs) == 0 || len(p.Tree.Entries) == 0)) || (delta && len(p.Tree.Entries) == 0 && p.Tree.BaseTree != p.Tree.SHA) || !validSHA(p.Commit.SHA) || p.Commit.Tree != p.Tree.SHA || strings.TrimSpace(p.Commit.Message) == "" {
		return errors.New("object package is incomplete")
	}
	seen := make(map[string]struct{}, len(p.Tree.Entries))
	blobSHAs := make(map[string]struct{}, len(p.Blobs))
	total := 0
	totalPathBytes := 0
	for _, blob := range p.Blobs {
		if blob.Encoding != "base64" || !validSHA(blob.SHA) {
			return errors.New("blob metadata is invalid")
		}
		content, err := base64.StdEncoding.DecodeString(blob.Content)
		if err != nil || len(content) > MaxBlobBytes {
			return errors.New("blob content is invalid or too large")
		}
		total += len(content)
		if total > MaxTotalBytes || gitBlobSHA(content) != blob.SHA {
			return errors.New("blob hash or package bounds are invalid")
		}
		if _, exists := blobSHAs[blob.SHA]; exists {
			return errors.New("blob is duplicated")
		}
		blobSHAs[blob.SHA] = struct{}{}
	}
	for _, entry := range p.Tree.Entries {
		// A submodule pointer is a gitlink: type "commit", mode 160000, a valid
		// commit SHA resolved from the submodule's own repository, and NO bundled
		// blob (GitHub resolves it by SHA). Everything else is a blob entry with a
		// blob mode. (Trello card 334.)
		isSubmodule := entry.Type == "commit" && entry.Mode == submoduleTreeMode
		if isSubmodule {
			if !validPath(entry.Path) || (entry.Delete && (!delta || entry.SHA != "")) || (!entry.Delete && !validSHA(entry.SHA)) {
				return errors.New("tree entry is invalid")
			}
		} else {
			if !validPath(entry.Path) || entry.Type != "blob" || !validMode(entry.Mode) || (entry.Delete && (!delta || entry.SHA != "")) || (!entry.Delete && !validSHA(entry.SHA)) {
				return errors.New("tree entry is invalid")
			}
			if !entry.Delete {
				if _, exists := blobSHAs[entry.SHA]; !exists && !delta {
					return errors.New("tree entry references a blob outside the package")
				}
			}
		}
		if _, exists := seen[entry.Path]; exists {
			return errors.New("tree entry path is duplicated")
		}
		totalPathBytes += len(entry.Path)
		if totalPathBytes > MaxTreePathBytes {
			return errors.New("tree paths exceed package bounds")
		}
		seen[entry.Path] = struct{}{}
	}
	for _, sha := range p.Commit.Parents {
		if !validSHA(sha) {
			return errors.New("commit parent is invalid")
		}
	}
	if !validSignature(p.Commit.Author) || !validSignature(p.Commit.Committer) {
		return errors.New("commit identity is invalid")
	}
	if gitCommitSHA(p.Commit) != p.Commit.SHA {
		return errors.New("commit hash does not match the immutable commit fields")
	}
	return nil
}

func validPath(value string) bool {
	if value == "" || len(value) > MaxPathBytes || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.ContainsRune(value, '\x00') {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// submoduleTreeMode is the git tree mode for a gitlink (submodule pointer),
// carried as a type:"commit" tree entry with no bundled blob. (Trello card 334.)
const submoduleTreeMode = "160000"

// emptyTreeSHA is git's well-known hash of the empty tree. A shape packet whose
// tree is empty must carry exactly this SHA, which is what makes "no entries"
// verifiable rather than merely absent.
const emptyTreeSHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

func validMode(value string) bool {
	switch value {
	case "100644", "100755", "120000":
		return true
	default:
		return false
	}
}

func validSignature(value Signature) bool {
	return strings.TrimSpace(value.Name) != "" && strings.Contains(value.Email, "@") && strings.TrimSpace(value.Date) != ""
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func gitBlobSHA(content []byte) string {
	hash := sha1.New() // GitHub's Git database REST API identifies Git objects by Git SHA-1.
	fmt.Fprintf(hash, "blob %d\x00", len(content))
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

// Reparent sets the commit's parents and recomputes its identity.
//
// A commit's SHA is derived from its parents, so rewriting them without
// rehashing produces a packet whose declared identity is a lie — Validate
// refuses it, correctly. Reparenting lives HERE, beside the hash it must keep
// consistent, so no caller can change one without the other.
//
// Pass no parents for a root commit (an empty public repository has no HEAD to
// descend from, and referencing a nonexistent object would fail at publish).
func (p *Packet) Reparent(parents ...string) {
	p.Commit.Parents = parents
	p.Commit.SHA = gitCommitSHA(p.Commit)
}

func gitCommitSHA(commit Commit) string {
	var body strings.Builder
	fmt.Fprintf(&body, "tree %s\n", commit.Tree)
	for _, parent := range commit.Parents {
		fmt.Fprintf(&body, "parent %s\n", parent)
	}
	fmt.Fprintf(&body, "author %s\n", gitSignature(commit.Author))
	fmt.Fprintf(&body, "committer %s\n\n", gitSignature(commit.Committer))
	body.WriteString(commit.Message)
	content := []byte(body.String())
	hash := sha1.New() // GitHub's Git database REST API identifies Git objects by Git SHA-1.
	fmt.Fprintf(hash, "commit %d\x00", len(content))
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}

func gitSignature(signature Signature) string {
	parsed, err := time.Parse(time.RFC3339, signature.Date)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s <%s> %d %s", signature.Name, signature.Email, parsed.Unix(), parsed.Format("-0700"))
}
