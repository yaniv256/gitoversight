package gitread

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// NewUnixProxy returns an HTTP reverse proxy whose only network destination is
// the privileged worker's Unix socket. Installation credentials never enter
// the public API process.
func NewUnixProxy(socketPath string) http.Handler {
	target := &url.URL{Scheme: "http", Host: "gitread.worker"}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
		MaxIdleConns:       8,
		IdleConnTimeout:    30 * time.Second,
	}
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(response, "repository read unavailable", http.StatusBadGateway)
	}
	return proxy
}
