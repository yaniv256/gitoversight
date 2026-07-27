package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareWritesOwnerOnlyHashBoundReviewBundle(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	redirect := "https://gitoversight.example.com/bootstrap/github-app/callback"
	var output bytes.Buffer
	if err := run(context.Background(), []string{
		"--prepare",
		"--redirect-url", redirect,
		"--bundle-dir", bundle,
	}, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &output); err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(output.String())) != 64 {
		t.Fatalf("digest output = %q", output.String())
	}
	info, err := os.Stat(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("bundle mode = %o", info.Mode().Perm())
	}
	for _, name := range []string{packetFilename, registrationHTMLFilename} {
		payload, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		fileInfo, err := os.Stat(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm() != 0o600 || len(payload) == 0 {
			t.Fatalf("%s mode=%o size=%d", name, fileInfo.Mode().Perm(), len(payload))
		}
	}
	packet, digest, err := readReviewedPacket(bundle, strings.TrimSpace(output.String()))
	if err != nil {
		t.Fatal(err)
	}
	if packet.Manifest.RedirectURL != redirect || digest != strings.TrimSpace(output.String()) {
		t.Fatalf("reviewed packet mismatch")
	}
}

func TestPrepareRefusesOverwriteAndConflictingModes(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	args := []string{
		"--prepare",
		"--redirect-url", "https://gitoversight.example.com/bootstrap/github-app/callback",
		"--bundle-dir", bundle,
	}
	deps := dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}
	if err := run(context.Background(), args, deps, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), args, deps, &bytes.Buffer{}); err == nil {
		t.Fatal("overwrote reviewed bundle")
	}
	if err := run(context.Background(), append(args, "--serve"), deps, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted conflicting modes")
	}
}

func TestServeRequiresRootAndExactDigestBeforeNetworkOrSecrets(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	prepare := []string{
		"--prepare",
		"--redirect-url", "https://gitoversight.example.com/bootstrap/github-app/callback",
		"--bundle-dir", bundle,
	}
	var digest bytes.Buffer
	if err := run(context.Background(), prepare, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &digest); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		euid   int
		digest string
	}{
		{name: "non-root", euid: 1002, digest: strings.TrimSpace(digest.String())},
		{name: "wrong digest", euid: 0, digest: strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			listenCalls := 0
			deps := dependencies{
				euid: func() int { return test.euid },
				listen: func(string, string) (listener, error) {
					listenCalls++
					return nil, nil
				},
			}
			err := run(context.Background(), []string{
				"--serve",
				"--bundle-dir", bundle,
				"--packet-digest", test.digest,
				"--secret-dir", filepath.Join(t.TempDir(), "github-app"),
			}, deps, &bytes.Buffer{})
			if err == nil || listenCalls != 0 {
				t.Fatalf("err=%v listenCalls=%d", err, listenCalls)
			}
		})
	}
}

func TestServeReportsListenAddressAndCause(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	var digest bytes.Buffer
	if err := run(context.Background(), []string{
		"--prepare",
		"--redirect-url", "https://gitoversight.com/bootstrap/github-app/callback",
		"--bundle-dir", bundle,
	}, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &digest); err != nil {
		t.Fatal(err)
	}

	listenErr := errors.New("address already in use")
	err := run(context.Background(), []string{
		"--serve",
		"--bundle-dir", bundle,
		"--packet-digest", strings.TrimSpace(digest.String()),
		"--secret-dir", filepath.Join(t.TempDir(), "github-app"),
		"--listen", "127.0.0.1:17446",
	}, dependencies{
		euid: func() int { return 0 },
		listen: func(string, string) (listener, error) {
			return nil, listenErr
		},
	}, &bytes.Buffer{})
	if !errors.Is(err, listenErr) || !strings.Contains(err.Error(), "127.0.0.1:17446") {
		t.Fatalf("listen error = %v", err)
	}
}

func TestVerifyChecksTheExactReviewedPacketWithoutNetworkOrSecrets(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	var digest bytes.Buffer
	if err := run(context.Background(), []string{
		"--prepare",
		"--redirect-url", "https://gitoversight.com/bootstrap/github-app/callback",
		"--bundle-dir", bundle,
	}, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &digest); err != nil {
		t.Fatal(err)
	}

	want := strings.TrimSpace(digest.String())
	listenCalls := 0
	var verified bytes.Buffer
	deps := dependencies{
		euid: func() int { return 1002 },
		listen: func(string, string) (listener, error) {
			listenCalls++
			return nil, nil
		},
	}
	if err := run(context.Background(), []string{
		"--verify",
		"--bundle-dir", bundle,
		"--packet-digest", want,
	}, deps, &verified); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(verified.String()) != want || listenCalls != 0 {
		t.Fatalf("verified=%q listenCalls=%d", verified.String(), listenCalls)
	}
	if err := run(context.Background(), []string{
		"--verify",
		"--bundle-dir", bundle,
		"--packet-digest", strings.Repeat("0", 64),
	}, deps, &bytes.Buffer{}); err == nil {
		t.Fatal("verified a packet under the wrong digest")
	}
}

func TestVerifyRejectsRegistrationPageThatDoesNotMatchReviewedPacket(t *testing.T) {
	t.Parallel()
	bundle := filepath.Join(t.TempDir(), "review-bundle")
	var digest bytes.Buffer
	if err := run(context.Background(), []string{
		"--prepare",
		"--redirect-url", "https://gitoversight.com/bootstrap/github-app/callback",
		"--bundle-dir", bundle,
	}, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &digest); err != nil {
		t.Fatal(err)
	}

	registrationPage := filepath.Join(bundle, registrationHTMLFilename)
	if err := os.WriteFile(registrationPage, []byte("<html>tampered</html>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{
		"--verify",
		"--bundle-dir", bundle,
		"--packet-digest", strings.TrimSpace(digest.String()),
	}, dependencies{euid: func() int { return 1002 }}, &bytes.Buffer{}); err == nil {
		t.Fatal("verified a registration page that did not match the reviewed packet")
	}
}

func TestServeConvertsOnceStoresSecretsAndReturnsOnlyRedactedReceipt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	bundle := filepath.Join(root, "review-bundle")
	redirect := "https://gitoversight.example.com/bootstrap/github-app/callback"
	var digest bytes.Buffer
	if err := run(context.Background(), []string{
		"--prepare", "--redirect-url", redirect, "--bundle-dir", bundle,
	}, dependencies{euid: func() int { return 1002 }, randomness: rand.Reader}, &digest); err != nil {
		t.Fatal(err)
	}
	packet, _, err := readReviewedPacket(bundle, strings.TrimSpace(digest.String()))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/app-manifests/test-code/conversions" {
			t.Errorf("unexpected conversion request %s %s", request.Method, request.URL.Path)
		}
		response.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(response, `{
			"id":42,
			"slug":"yaniv-gitoversight-broker",
			"client_id":"Iv23f8doAlphaNumer1c",
			"client_secret":"client-secret-value",
			"webhook_secret":"webhook-secret-value",
			"pem":"-----BEGIN RSA PRIVATE KEY-----\\nprivate-key-value\\n-----END RSA PRIVATE KEY-----\\n",
			"html_url":"https://github.com/apps/yaniv-gitoversight-broker",
			"name":"Yaniv Git Oversight Broker",
			"owner":{"login":"yaniv256"}
		}`)
	}))
	defer api.Close()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	secretDir := filepath.Join(root, "secrets", "github-app")
	var receipt bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(context.Background(), []string{
			"--serve",
			"--bundle-dir", bundle,
			"--packet-digest", strings.TrimSpace(digest.String()),
			"--secret-dir", secretDir,
			"--listen", "127.0.0.1:1",
			"--api-base-url", api.URL,
		}, dependencies{
			euid:   func() int { return 0 },
			listen: func(string, string) (listener, error) { return socket, nil },
		}, &receipt)
	}()
	registration := fmt.Sprintf("http://%s/bootstrap/github-app/register", socket.Addr())
	registrationResponse, err := http.Get(registration)
	if err != nil {
		t.Fatal(err)
	}
	registrationBody, err := io.ReadAll(registrationResponse.Body)
	_ = registrationResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if registrationResponse.StatusCode != http.StatusOK || !strings.Contains(string(registrationBody), "Create the private GitHub App") {
		t.Fatalf("registration status=%d body=%q", registrationResponse.StatusCode, registrationBody)
	}
	if registrationResponse.Header.Get("Cache-Control") != "no-store" || !strings.Contains(registrationResponse.Header.Get("Content-Security-Policy"), "form-action https://github.com") {
		t.Fatalf("registration security headers = %#v", registrationResponse.Header)
	}
	callback := fmt.Sprintf("http://%s/bootstrap/github-app/callback?state=%s&code=test-code", socket.Addr(), packet.State)
	response, err := http.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d", response.StatusCode)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(secretDir, "github-app.pem")); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"client-secret-value", "webhook-secret-value", "private-key-value"} {
		if strings.Contains(receipt.String(), forbidden) {
			t.Fatalf("receipt exposed secret material: %s", receipt.String())
		}
	}
	if !strings.Contains(receipt.String(), `"app_id":42`) || !strings.Contains(receipt.String(), strings.TrimSpace(digest.String())) {
		t.Fatalf("redacted receipt = %s", receipt.String())
	}
}
