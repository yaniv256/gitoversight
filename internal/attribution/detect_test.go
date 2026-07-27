package attribution_test

import (
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/attribution"
)

func TestContainsRecognizesIdentityAcrossPublicMetadataForms(t *testing.T) {
	identities := []attribution.Identity{{Name: "zara"}, {Name: "Zara"}, {Email: "zara@example.com"}}
	for _, value := range []string{
		"zara/feature", "Authored by Zara", "Co-authored-by: ZARA <private@example.test>",
		"reviewer=zara", "contact ZARA@EXAMPLE.COM", "— Zara",
	} {
		if !attribution.Contains(value, identities) {
			t.Fatalf("expected identity detection in %q", value)
		}
	}
	for _, value := range []string{"lazaran docs", "zarathustra", "public release"} {
		if attribution.Contains(value, identities) {
			t.Fatalf("unexpected identity detection in %q", value)
		}
	}
}

// The email matcher is asserted on its own because punctuation normalization
// makes an address match the name matcher too: "zara@example.com" normalizes to
// " zara example com ", which a Name identity already catches. Without an
// email-only identity set, an email-matching regression would stay green.
func TestContainsMatchesEmailWithoutNameIdentity(t *testing.T) {
	identities := []attribution.Identity{{Email: "zara@example.com"}}
	for _, value := range []string{"contact zara@example.com", "contact ZARA@EXAMPLE.COM"} {
		if !attribution.Contains(value, identities) {
			t.Fatalf("expected email detection in %q", value)
		}
	}
	for _, value := range []string{"reviewer=zara", "Authored by Zara"} {
		if attribution.Contains(value, identities) {
			t.Fatalf("unexpected email detection in %q", value)
		}
	}
}
