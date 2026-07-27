package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppBootstrapHasASeparateReproducibleEC2Artifact(t *testing.T) {
	t.Parallel()

	packager := read(t, "package-app-bootstrap.sh")
	requireContains(t, packager,
		"gitoversight-app-bootstrap",
		"CGO_ENABLED=0 GOOS=linux GOARCH=\"$target_arch\" go build -trimpath -ldflags='-buildid='",
		"tar --sort=name",
		"--owner=0 --group=0 --numeric-owner",
		"sha256sum \"$output\"",
	)
	if strings.Contains(packager, "manifest-packet.json") || strings.Contains(packager, "github-app.pem") {
		t.Fatal("bootstrap artifact must not package a reviewed packet or generated secret")
	}

	installer := read(t, "install-app-bootstrap.sh")
	requireContains(t, installer,
		"install-app-bootstrap.sh REVIEW_BUNDLE PACKET_DIGEST",
		"gitoversight-app-bootstrap",
		"/etc/gitoversight/app-bootstrap",
		"/etc/gitoversight/app-bootstrap.digest",
		"gitoversight-app-bootstrap.service",
		"systemctl daemon-reload",
	)

	launcher := read(t, "serve-app-bootstrap.sh")
	requireContains(t, launcher,
		"/etc/gitoversight/app-bootstrap.digest",
		"--bundle-dir /etc/gitoversight/app-bootstrap",
		"--secret-dir /etc/gitoversight-secrets/github-app",
		"--listen 127.0.0.1:17446",
	)

	unit := read(t, "gitoversight-app-bootstrap.service")
	requireContains(t, unit,
		"User=root",
		"ExecStart=/usr/local/sbin/gitoversight-serve-app-bootstrap",
		"RuntimeMaxSec=15m",
		"ProtectSystem=strict",
		"ReadOnlyPaths=/etc/gitoversight/app-bootstrap /etc/gitoversight/app-bootstrap.digest",
		"ReadWritePaths=/etc/gitoversight-secrets",
		"RestrictAddressFamilies=AF_INET AF_INET6",
		"NoNewPrivileges=yes",
	)
}

func TestFinalRuntimeArtifactExcludesOneShotAppBootstrapService(t *testing.T) {
	t.Parallel()

	runtimePackager := read(t, "package.sh")
	runtimeInstaller := read(t, "install.sh")
	for _, payload := range []struct {
		name string
		body string
	}{
		{name: "runtime packager", body: runtimePackager},
		{name: "runtime installer", body: runtimeInstaller},
	} {
		requireContains(t, payload.body,
			"gitoversight-api.service",
			"gitoversight-worker.service",
			"gitoversight-checkpoint.service",
			"gitoversight-notify.service",
		)
		if strings.Contains(payload.body, "gitoversight-*.service") {
			t.Fatalf("%s uses a service wildcard that can include the one-shot bootstrap unit", payload.name)
		}
	}
	if strings.Contains(runtimePackager, "gitoversight-app-bootstrap.service") || strings.Contains(runtimeInstaller, "gitoversight-app-bootstrap.service") {
		t.Fatal("final runtime path includes the one-shot App-bootstrap service")
	}
}

func TestAppBootstrapInstallerCopiesOnlyAnExactOwnerOnlyReviewedBundle(t *testing.T) {
	t.Parallel()

	installer := read(t, "install-app-bootstrap.sh")
	for _, required := range []string{
		"manifest-packet.json",
		"register-github-app.html",
		"^[0-9a-f]{64}$",
		"stat -c %a",
		"stat -c %u",
		"install -d -m 0700",
		"install -m 0600",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer missing %q", required)
		}
	}
	stateGuard := strings.Index(installer, "App bootstrap state or credentials already exist; refusing overwrite")
	binaryInstall := strings.Index(installer, "install -D -m 0755 \"$root/bin/gitoversight-app-bootstrap\"")
	if stateGuard < 0 || binaryInstall < 0 || stateGuard > binaryInstall {
		t.Fatal("installer mutates the installed binary before checking for existing bootstrap state")
	}
	if !strings.Contains(installer, "find \"$review_bundle\" -mindepth 1 -maxdepth 1 | wc -l") {
		t.Fatal("installer does not reject non-file extras in the reviewed bundle")
	}
}

func TestPublicEdgesRouteOnlyExactAppBootstrapPaths(t *testing.T) {
	t.Parallel()

	launcher := read(t, "serve-app-bootstrap.sh")
	nginx := read(t, "nginx.conf.template")
	requireContains(t, nginx,
		"location = /bootstrap/github-app/register",
		"location = /bootstrap/github-app/callback",
		"proxy_pass http://127.0.0.1:17446;",
	)
	if strings.Contains(nginx, "location /bootstrap/github-app/") || strings.Contains(nginx, "location ^~ /bootstrap/github-app/") {
		t.Fatal("Nginx bootstrap routing is broader than the two reviewed paths")
	}

	caddy := read(t, "Caddyfile")
	requireContains(t, caddy,
		"@app_bootstrap path /bootstrap/github-app/register /bootstrap/github-app/callback",
		"reverse_proxy @app_bootstrap 127.0.0.1:17446",
		"reverse_proxy 127.0.0.1:17445",
	)

	for name, payload := range map[string]string{
		"launcher": launcher,
		"Nginx":    nginx,
		"Caddy":    caddy,
	} {
		if strings.Contains(payload, "127.0.0.1:8787") {
			t.Fatalf("%s still uses the shared actionsjson-com loopback port", name)
		}
	}
}

func TestAppBootstrapDeployFilesContainNoSecretMaterial(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"package-app-bootstrap.sh",
		"install-app-bootstrap.sh",
		"serve-app-bootstrap.sh",
		"gitoversight-app-bootstrap.service",
	} {
		payload, err := os.ReadFile(filepath.Join(deployRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"github_pat_", "ghp_", "begin rsa private key", "client-secret-value", "webhook-secret-value"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s contains secret-shaped material %q", name, forbidden)
			}
		}
	}
}
