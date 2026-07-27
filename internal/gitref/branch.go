package gitref

import "strings"

// BranchName canonicalizes either a short branch name or a fully qualified
// heads ref to the short name used by policy and GitHub's ref endpoints.
func BranchName(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "refs/heads/") {
		value = strings.TrimPrefix(value, "refs/heads/")
	}
	// A qualified branch is accepted exactly once. Reject nested or other
	// qualified refs so repeated validation at privileged boundaries cannot
	// transform the branch identity after policy authorization.
	if value == "" || strings.HasPrefix(value, "refs/") {
		return ""
	}
	return value
}
