package searchembed

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"agent-kanban.dev", []string{"agent", "kanban", "dev"}},
		{"ChromeLauncher", []string{"chrome", "launcher"}},
		{"snake_case_name", []string{"snake", "case", "name"}},
		{"HTTPServer", []string{"http", "server"}},
		{"yaniv256/gitoversight.dev", []string{"yaniv", "gitoversight", "dev"}},
		{"Voice assistant, browser control!", []string{"voice", "assistant", "browser", "control"}},
		// Pure-numeric and one-char tokens are dropped.
		{"a 1 42 x", nil},
		{"v1.54.0 sha256", []string{"sha"}},
		{"", nil},
	}
	for _, tc := range cases {
		got := Tokenize(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Tokenize(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
