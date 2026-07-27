// Package searchembed is the corpus-trained text-embedding and search core
// for repo titles, descriptions, and READMEs. Pure stdlib: deterministic
// sparse random-indexing vectors, co-occurrence enrichment, IDF weighting,
// int8 quantization, and a min-across-keywords cosine ranking merged with
// full-text hits.
package searchembed

import (
	"strings"
	"unicode"
)

// Tokenize splits s into lowercase word tokens. Boundaries are camelCase
// transitions, snake_case, kebab-case, dot.separated segments, whitespace,
// letter/digit transitions, and any other punctuation. Pure-numeric tokens
// and single-character tokens are dropped.
func Tokenize(s string) []string {
	var tokens []string
	var run []rune
	flush := func() {
		if len(run) > 0 {
			tokens = appendWordParts(tokens, run)
			run = run[:0]
		}
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			run = append(run, r)
		} else {
			flush()
		}
	}
	flush()
	return tokens
}

// appendWordParts splits one alphanumeric run at camelCase and letter/digit
// boundaries, lowercases the parts, and appends the parts that survive the
// length and numeric filters.
func appendWordParts(tokens []string, run []rune) []string {
	start := 0
	emit := func(end int) {
		part := run[start:end]
		start = end
		if len(part) < 2 || allDigits(part) {
			return
		}
		tokens = append(tokens, strings.ToLower(string(part)))
	}
	for i := 1; i < len(run); i++ {
		prev, cur := run[i-1], run[i]
		switch {
		case unicode.IsLower(prev) && unicode.IsUpper(cur):
			emit(i) // camelCase: fooBar -> foo|Bar
		case unicode.IsDigit(prev) != unicode.IsDigit(cur):
			emit(i) // letter/digit transition: sha256 -> sha|256
		case unicode.IsUpper(prev) && unicode.IsUpper(cur) && i+1 < len(run) && unicode.IsLower(run[i+1]):
			emit(i) // acronym boundary: HTTPServer -> HTTP|Server
		}
	}
	emit(len(run))
	return tokens
}

func allDigits(part []rune) bool {
	for _, r := range part {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
