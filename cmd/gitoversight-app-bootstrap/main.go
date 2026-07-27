package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/appbootstrap"
)

const (
	packetFilename           = "manifest-packet.json"
	registrationHTMLFilename = "register-github-app.html"
	registrationPath         = "/bootstrap/github-app/register"
	maxPacketBytes           = 128 << 10
	maxRegistrationHTMLBytes = 128 << 10
)

type listener = net.Listener

type dependencies struct {
	euid       func() int
	randomness io.Reader
	listen     func(string, string) (listener, error)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	deps := dependencies{euid: os.Geteuid, randomness: rand.Reader, listen: net.Listen}
	if err := run(ctx, os.Args[1:], deps, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, deps dependencies, output io.Writer) error {
	flags := flag.NewFlagSet("gitoversight-app-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	prepare := flags.Bool("prepare", false, "prepare a reviewed GitHub App manifest bundle")
	verify := flags.Bool("verify", false, "verify an exact reviewed GitHub App manifest bundle without network or secret writes")
	serve := flags.Bool("serve", false, "serve the one-shot GitHub App manifest callback")
	redirectURL := flags.String("redirect-url", "", "exact reviewed HTTPS manifest callback URL")
	bundleDir := flags.String("bundle-dir", "", "absolute path to the reviewed manifest bundle")
	packetDigest := flags.String("packet-digest", "", "exact SHA-256 digest of the reviewed manifest packet")
	secretDir := flags.String("secret-dir", "/etc/gitoversight-secrets/github-app", "root-owned destination for the App credential bundle")
	listenAddress := flags.String("listen", "127.0.0.1:8787", "loopback callback listener")
	apiBaseURL := flags.String("api-base-url", "https://api.github.com", "GitHub API base URL")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse App bootstrap arguments: %w", err)
	}
	modeCount := 0
	for _, selected := range []bool{*prepare, *verify, *serve} {
		if selected {
			modeCount++
		}
	}
	if flags.NArg() != 0 || modeCount != 1 {
		return errors.New("exactly one of --prepare, --verify, or --serve is required")
	}
	if !validAbsolutePath(*bundleDir) {
		return errors.New("--bundle-dir must be an absolute non-root path")
	}
	if *prepare {
		if *redirectURL == "" || *packetDigest != "" {
			return errors.New("--prepare requires --redirect-url and forbids --packet-digest")
		}
		if deps.randomness == nil {
			return errors.New("bootstrap randomness is unavailable")
		}
		digest, err := prepareReviewBundle(*bundleDir, *redirectURL, deps.randomness)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, digest)
		return err
	}
	if *verify {
		if *redirectURL != "" || len(*packetDigest) != 64 {
			return errors.New("--verify requires the exact --packet-digest and forbids --redirect-url")
		}
		_, digest, err := readReviewedPacket(*bundleDir, *packetDigest)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, digest)
		return err
	}
	if deps.euid == nil || deps.euid() != 0 {
		return errors.New("--serve requires root")
	}
	if *redirectURL != "" || len(*packetDigest) != 64 {
		return errors.New("--serve requires the exact --packet-digest and forbids --redirect-url")
	}
	packet, digest, err := readReviewedPacket(*bundleDir, *packetDigest)
	if err != nil {
		return err
	}
	return serveOnce(ctx, deps, packet, digest, *secretDir, *listenAddress, *apiBaseURL, output)
}

func prepareReviewBundle(path, redirectURL string, randomness io.Reader) (string, error) {
	packet, err := appbootstrap.PrepareManifestPacket(redirectURL, randomness)
	if err != nil {
		return "", err
	}
	digest, err := appbootstrap.ManifestPacketDigest(packet)
	if err != nil {
		return "", err
	}
	packetJSON, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		return "", errors.New("encode manifest packet")
	}
	html, err := appbootstrap.RenderRegistrationHTML(packet)
	if err != nil {
		return "", err
	}
	if err := publishReviewBundle(path, map[string][]byte{
		packetFilename:           append(packetJSON, '\n'),
		registrationHTMLFilename: html,
	}); err != nil {
		return "", err
	}
	return digest, nil
}

func publishReviewBundle(path string, files map[string][]byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return errors.New("create manifest bundle parent")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("manifest review bundle already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("inspect manifest review bundle")
	}
	temporary, err := os.MkdirTemp(parent, ".github-app-review-*")
	if err != nil {
		return errors.New("create manifest review staging directory")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return errors.New("secure manifest review staging directory")
	}
	for _, name := range []string{packetFilename, registrationHTMLFilename} {
		payload, ok := files[name]
		if !ok {
			return errors.New("manifest review bundle is incomplete")
		}
		if err := writeOwnerOnlyFile(filepath.Join(temporary, name), payload); err != nil {
			return fmt.Errorf("write manifest review file %s", name)
		}
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("publish manifest review bundle")
	}
	published = true
	return nil
}

func readReviewedPacket(path, expectedDigest string) (appbootstrap.ManifestPacket, string, error) {
	if !validAbsolutePath(path) {
		return appbootstrap.ManifestPacket{}, "", errors.New("manifest bundle path is invalid")
	}
	directory, err := os.Lstat(path)
	if err != nil || !directory.IsDir() || directory.Mode().Perm()&0o077 != 0 {
		return appbootstrap.ManifestPacket{}, "", errors.New("manifest bundle is not an owner-only directory")
	}
	packetPath := filepath.Join(path, packetFilename)
	info, err := os.Lstat(packetPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxPacketBytes {
		return appbootstrap.ManifestPacket{}, "", errors.New("manifest packet file is not an owner-only bounded regular file")
	}
	payload, err := os.ReadFile(packetPath)
	if err != nil {
		return appbootstrap.ManifestPacket{}, "", errors.New("read manifest packet")
	}
	var packet appbootstrap.ManifestPacket
	if err := json.Unmarshal(payload, &packet); err != nil {
		return appbootstrap.ManifestPacket{}, "", errors.New("decode manifest packet")
	}
	if err := appbootstrap.ValidateManifestPacket(packet, strings.ToLower(expectedDigest)); err != nil {
		return appbootstrap.ManifestPacket{}, "", err
	}
	registrationPath := filepath.Join(path, registrationHTMLFilename)
	registrationInfo, err := os.Lstat(registrationPath)
	if err != nil || !registrationInfo.Mode().IsRegular() || registrationInfo.Mode().Perm()&0o077 != 0 || registrationInfo.Size() > maxRegistrationHTMLBytes {
		return appbootstrap.ManifestPacket{}, "", errors.New("registration page file is not an owner-only bounded regular file")
	}
	reviewedRegistrationHTML, err := os.ReadFile(registrationPath)
	if err != nil {
		return appbootstrap.ManifestPacket{}, "", errors.New("read registration page")
	}
	expectedRegistrationHTML, err := appbootstrap.RenderRegistrationHTML(packet)
	if err != nil {
		return appbootstrap.ManifestPacket{}, "", err
	}
	if !bytes.Equal(reviewedRegistrationHTML, expectedRegistrationHTML) {
		return appbootstrap.ManifestPacket{}, "", errors.New("registration page does not match reviewed manifest packet")
	}
	digest, err := appbootstrap.ManifestPacketDigest(packet)
	if err != nil {
		return appbootstrap.ManifestPacket{}, "", err
	}
	return packet, digest, nil
}

func serveOnce(ctx context.Context, deps dependencies, packet appbootstrap.ManifestPacket, digest, secretDir, address, apiBaseURL string, output io.Writer) error {
	if !validLoopbackAddress(address) {
		return errors.New("--listen must be a concrete loopback TCP address")
	}
	store, err := appbootstrap.NewSecretDirectoryStore(secretDir)
	if err != nil {
		return err
	}
	converter, err := appbootstrap.NewGitHubConverter(apiBaseURL, &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return err
	}
	handler, err := appbootstrap.NewCallbackHandler(packet.State, converter, store)
	if err != nil {
		return err
	}
	registrationHTML, err := appbootstrap.RenderRegistrationHTML(packet)
	if err != nil {
		return err
	}
	bootstrapHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != registrationPath {
			handler.ServeHTTP(response, request)
			return
		}
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; frame-ancestors 'none'")
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(registrationHTML)
	})
	listen := deps.listen
	if listen == nil {
		listen = net.Listen
	}
	socket, err := listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for one-shot GitHub App callback on %s: %w", address, err)
	}
	server := &http.Server{
		Handler:           bootstrapHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(socket) }()
	var result appbootstrap.AttemptResult
	select {
	case <-ctx.Done():
		_ = server.Shutdown(context.Background())
		return errors.New("GitHub App bootstrap callback timed out")
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("serve GitHub App bootstrap callback")
		}
		return errors.New("GitHub App bootstrap callback stopped before completion")
	case result = <-handler.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}
	if !result.Success {
		return fmt.Errorf("GitHub App bootstrap failed closed: %s", result.Code)
	}
	return json.NewEncoder(output).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		PacketDigest  string `json:"packet_digest"`
		AppID         int64  `json:"app_id"`
		Slug          string `json:"slug"`
		InstallURL    string `json:"install_url"`
	}{1, digest, result.AppID, result.Slug, result.InstallURL})
}

func writeOwnerOnlyFile(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func validAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) != "/"
}

func validLoopbackAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
