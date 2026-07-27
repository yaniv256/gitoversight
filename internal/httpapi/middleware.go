package httpapi

import (
	"net/http"
	"strings"
)

var ambiguousForwardingHeaders = []string{
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Original-Host", "X-Original-URL",
}

// RejectForwardingAmbiguity keeps the HTTP Message Signature authority and
// target components tied to the request the selected TLS edge actually received.
// The trusted reverse proxy removes these headers before forwarding; direct or misconfigured
// proxy traffic fails closed.
func RejectForwardingAmbiguity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.TrimSpace(request.Host) == "" {
			http.Error(response, "ambiguous request target", http.StatusBadRequest)
			return
		}
		for _, name := range ambiguousForwardingHeaders {
			if len(request.Header.Values(name)) != 0 {
				http.Error(response, "ambiguous request target", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(response, request)
	})
}

func LimitConcurrent(maximum int, next http.Handler) http.Handler {
	if maximum <= 0 {
		maximum = 32
	}
	semaphore := make(chan struct{}, maximum)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case semaphore <- struct{}{}:
			defer func() { <-semaphore }()
			next.ServeHTTP(response, request)
		default:
			response.Header().Set("Retry-After", "1")
			http.Error(response, "service overloaded", http.StatusServiceUnavailable)
		}
	})
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}
