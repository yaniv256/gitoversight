package appauth

import "testing"

func TestValidPKCEVerifier(t *testing.T) {
	t.Parallel()
	valid43 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	valid128 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" +
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if len(valid43) != 43 || len(valid128) != 128 {
		t.Fatal("test fixture lengths are wrong")
	}
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty", value: "", want: false},
		{name: "short", value: valid43[:42], want: false},
		{name: "minimum", value: valid43, want: true},
		{name: "maximum", value: valid128, want: true},
		{name: "long", value: valid128 + "a", want: false},
		{name: "space", value: valid43[:42] + " ", want: false},
		{name: "non ASCII", value: valid43[:42] + "é", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validPKCEVerifier(test.value); got != test.want {
				t.Fatalf("validPKCEVerifier() = %v, want %v", got, test.want)
			}
		})
	}
}
