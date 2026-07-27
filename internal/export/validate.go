package governanceexport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
)

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)github_pat_[a-z0-9_]{20,}`),
	regexp.MustCompile(`(?i)gh[pousr]_[a-z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

type File struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Content []byte `json:"content"`
}

type Bundle struct {
	Files       []File `json:"files"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	AuthorName  string `json:"author_name"`
	AuthorEmail string `json:"author_email"`
}

type AgentIdentity struct {
	Name  string
	Email string
}

func Validate(bundle Bundle, agents []AgentIdentity) error {
	if len(bundle.Files) == 0 || bundle.Title == "" || bundle.AuthorName == "" || bundle.AuthorEmail == "" {
		return errors.New("export bundle is incomplete")
	}
	identities := attributionIdentities(agents)
	metadata := bundle.Title + "\n" + bundle.Body + "\n" + bundle.AuthorName + "\n" + bundle.AuthorEmail
	if attribution.Contains(metadata, identities) {
		return errors.New("public metadata contains agent attribution")
	}
	seen := make(map[string]struct{}, len(bundle.Files))
	for _, file := range bundle.Files {
		if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") {
			return fmt.Errorf("unsafe export path %q", file.Path)
		}
		if _, exists := seen[file.Path]; exists {
			return fmt.Errorf("duplicate export path %q", file.Path)
		}
		seen[file.Path] = struct{}{}
		if file.Mode != 0o100644 && file.Mode != 0o100755 {
			return fmt.Errorf("unsupported Git mode %o for %s", file.Mode, file.Path)
		}
		if strings.HasPrefix(file.Path, ".github/workflows/") {
			return fmt.Errorf("workflow requires separate explicit approval: %s", file.Path)
		}
		if strings.HasPrefix(string(file.Content), "version https://git-lfs.github.com/spec/") {
			return fmt.Errorf("LFS pointer requires separate explicit approval: %s", file.Path)
		}
		if attribution.Contains(string(file.Content), identities) {
			return fmt.Errorf("public file contains agent attribution: %s", file.Path)
		}
		for _, pattern := range credentialPatterns {
			if pattern.Match(file.Content) {
				return fmt.Errorf("public file contains credential material: %s", file.Path)
			}
		}
	}
	return nil
}

func attributionIdentities(agents []AgentIdentity) []attribution.Identity {
	result := make([]attribution.Identity, 0, len(agents)*2)
	for _, agent := range agents {
		result = append(result, attribution.Identity{Name: agent.Name}, attribution.Identity{Email: agent.Email})
	}
	return result
}

func Hash(bundle Bundle) (string, error) {
	copyBundle := bundle
	copyBundle.Files = append([]File(nil), bundle.Files...)
	sort.Slice(copyBundle.Files, func(i, j int) bool { return copyBundle.Files[i].Path < copyBundle.Files[j].Path })
	payload, err := json.Marshal(copyBundle)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
