package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHiveHTTPSenderDoesNotExposeProviderResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte("token=secret"))
	}))
	defer server.Close()
	sender := &hiveHTTPSender{endpoint: server.URL, token: "secret", client: &http.Client{Timeout: time.Second, Transport: server.Client().Transport}}
	if err := sender.Send(context.Background(), "zara", "event"); err == nil || err.Error() != "notification provider rejected delivery" {
		t.Fatalf("error = %v", err)
	}
}
