package governanceexport_test

import (
	"testing"

	governanceexport "github.com/yaniv256/gitoversight.dev/internal/export"
)

func TestPublicExportAcceptsOrdinaryFilesAndHumanMetadata(t *testing.T) {
	t.Parallel()
	bundle := governanceexport.Bundle{
		Files: []governanceexport.File{{Path: "README.md", Mode: 0o100644, Content: []byte("public docs")}},
		Title: "Public docs", Body: "Approved documentation.", AuthorName: "Yaniv Ben-Ami", AuthorEmail: "yaniv@example.com",
	}
	if err := governanceexport.Validate(bundle, []governanceexport.AgentIdentity{{Name: "Zara", Email: "zara@example.com"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPublicExportRejectsPrivateIdentityAndActiveContent(t *testing.T) {
	t.Parallel()
	tests := []governanceexport.Bundle{
		{Files: []governanceexport.File{{Path: "README.md", Mode: 0o100644, Content: []byte("ok")}}, Title: "Docs", Body: "— Zara", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: ".github/workflows/publish.yml", Mode: 0o100644, Content: []byte("name: publish")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: "link", Mode: 0o120000, Content: []byte("private")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: "asset.bin", Mode: 0o100644, Content: []byte("version https://git-lfs.github.com/spec/v1")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: "NOTES.md", Mode: 0o100644, Content: []byte("Prepared by agent Zara")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: "NOTES.md", Mode: 0o100644, Content: []byte("Authored by Zara")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
		{Files: []governanceexport.File{{Path: ".env", Mode: 0o100644, Content: []byte("GITHUB_TOKEN=github_pat_0123456789abcdefghijklmnopqrstuvwxyz")}}, Title: "Docs", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"},
	}
	for _, bundle := range tests {
		if err := governanceexport.Validate(bundle, []governanceexport.AgentIdentity{{Name: "Zara", Email: "zara@example.com"}}); err == nil {
			t.Fatalf("expected rejection for %#v", bundle)
		}
	}
}

func TestManifestHashChangesWithAnyAuthorityBearingField(t *testing.T) {
	t.Parallel()
	base := governanceexport.Bundle{Files: []governanceexport.File{{Path: "README.md", Mode: 0o100644, Content: []byte("one")}}, Title: "Docs", Body: "Body", AuthorName: "Yaniv", AuthorEmail: "yaniv@example.com"}
	first, err := governanceexport.Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Title = "Changed"
	second, err := governanceexport.Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("title change did not invalidate manifest hash")
	}
}
