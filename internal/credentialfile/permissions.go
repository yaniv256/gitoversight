package credentialfile

import (
	"os"
	"path/filepath"
	"strings"
)

const systemdCredentialRoot = "/run/credentials"

// PermissionsSafe accepts ordinary owner-only secret files and systemd's
// read-only credential copies. systemd protects each 0440 copy with a
// unit-private directory named after the full service unit.
func PermissionsSafe(path string, mode os.FileMode, credentialsDirectory string) bool {
	permissions := mode.Perm()
	if permissions&0o077 == 0 {
		return true
	}
	if permissions != 0o440 || credentialsDirectory == "" {
		return false
	}

	directory := filepath.Clean(credentialsDirectory)
	if !filepath.IsAbs(directory) || filepath.Dir(directory) != systemdCredentialRoot || !strings.HasSuffix(filepath.Base(directory), ".service") {
		return false
	}
	cleanPath := filepath.Clean(path)
	return filepath.IsAbs(cleanPath) && filepath.Dir(cleanPath) == directory
}
