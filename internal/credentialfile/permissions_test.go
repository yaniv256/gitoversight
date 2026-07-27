package credentialfile

import (
	"os"
	"testing"
)

func TestPermissionsSafeAcceptsOwnerOnlyFiles(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o400, 0o600, 0o700} {
		if !PermissionsSafe("/etc/gitoversight-secrets/key", mode, "") {
			t.Fatalf("mode %04o rejected", mode)
		}
	}
}

func TestPermissionsSafeAcceptsOnlyTheMatchingSystemdCredentialMount(t *testing.T) {
	t.Parallel()
	directory := "/run/credentials/gitoversight-worker.service"
	path := directory + "/vault-key"
	if !PermissionsSafe(path, 0o440, directory) {
		t.Fatal("systemd credential copy rejected")
	}
	for _, test := range []struct {
		name      string
		path      string
		mode      os.FileMode
		directory string
	}{
		{name: "ordinary group-readable file", path: "/etc/gitoversight-secrets/vault.key", mode: 0o440},
		{name: "world-readable credential", path: path, mode: 0o444, directory: directory},
		{name: "different unit", path: path, mode: 0o440, directory: "/run/credentials/gitoversight-api.service"},
		{name: "untrusted root", path: "/tmp/gitoversight-worker.service/vault-key", mode: 0o440, directory: "/tmp/gitoversight-worker.service"},
		{name: "unit suffix missing", path: "/run/credentials/gitoversight-worker/vault-key", mode: 0o440, directory: "/run/credentials/gitoversight-worker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if PermissionsSafe(test.path, test.mode, test.directory) {
				t.Fatal("unsafe permissions accepted")
			}
		})
	}
}
