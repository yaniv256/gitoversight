package attribution

import (
	"strings"
	"unicode"
)

// Identity is private provenance that must not cross a public publication
// boundary. Name may be either an internal agent ID or a display name.
type Identity struct {
	Name  string
	Email string
}

// Contains reports whether text contains a complete private identity token.
// Punctuation is treated as a separator so branch names, trailers, signatures,
// and structured prose receive the same fail-closed treatment.
func Contains(text string, identities []Identity) bool {
	lower := strings.ToLower(text)
	normalized := normalize(lower)
	for _, identity := range identities {
		if email := strings.ToLower(strings.TrimSpace(identity.Email)); email != "" && strings.Contains(lower, email) {
			return true
		}
		name := strings.TrimSpace(normalize(identity.Name))
		if name != "" && strings.Contains(normalized, " "+name+" ") {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	var result strings.Builder
	result.WriteByte(' ')
	space := true
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			result.WriteRune(r)
			space = false
			continue
		}
		if !space {
			result.WriteByte(' ')
			space = true
		}
	}
	if !space {
		result.WriteByte(' ')
	}
	return result.String()
}
