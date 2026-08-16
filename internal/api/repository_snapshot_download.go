package api

import (
	"errors"
	"net/http"

	"github.com/yaniv256/gitoversight.dev/internal/snapshotdownload"
)

// NewRepositorySnapshotDownloadHandler exposes only opaque one-time archive
// redemption. Authorization occurs when the URL is issued; the unguessable URL
// is the short-lived capability and is deleted on its first redemption.
func NewRepositorySnapshotDownloadHandler(store *snapshotdownload.Store) (http.Handler, error) {
	if store == nil {
		return nil, errors.New("repository snapshot download store is required")
	}
	return store, nil
}
