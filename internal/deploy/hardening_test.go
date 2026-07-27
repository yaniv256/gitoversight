package deploy_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const deployRoot = "../../deploy/ec2"

func read(t *testing.T, name string) string {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(deployRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func requireContains(t *testing.T, payload string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(payload, value) {
			t.Errorf("missing %q", value)
		}
	}
}

func TestEC2ServicesUseSeparateLeastPrivilegeIdentities(t *testing.T) {
	t.Parallel()

	api := read(t, "gitoversight-api.service")
	requireContains(t, api,
		"User=gitoversight-api", "Group=gitoversight-api",
		"SupplementaryGroups=", "gitoversight-worker", "gitoversight-checkpoint",
		"IPAddressAllow=localhost", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
		"ReadWritePaths=/var/lib/gitoversight-api", "NoNewPrivileges=yes",
		"ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes",
		"ProtectProc=invisible", "RestrictNamespaces=yes", "MemoryDenyWriteExecute=yes", "UMask=0077",
	)
	if strings.Contains(api, "LoadCredential=github-app-") || strings.Contains(api, "LoadCredential=notification-") {
		t.Fatal("public API service must not receive mutation or notification credentials")
	}

	worker := read(t, "gitoversight-worker.service")
	requireContains(t, worker,
		"User=gitoversight-worker", "Group=gitoversight-worker",
		"SupplementaryGroups=gitoversight-authority", "ReadWritePaths=/run/gitoversight-worker /run/gitoversight-authority /var/lib/gitoversight-worker", "UMask=0077",
		"LoadCredential=github-app-client-secret:", "LoadCredential=github-app-private-key:",
		"LoadCredential=vault-key:", "PrivateDevices=yes", "NoNewPrivileges=yes",
	)
	if strings.Contains(worker, "/var/lib/gitoversight-api") || strings.Contains(worker, "gitoversight-state") {
		t.Fatal("privileged worker must not have direct authority database access")
	}
	if strings.Contains(worker, "ListenStream=") || strings.Contains(worker, "0.0.0.0") {
		t.Fatal("privileged worker must not expose a network listener")
	}

	checkpoint := read(t, "gitoversight-checkpoint.service")
	requireContains(t, checkpoint,
		"User=gitoversight-checkpoint", "PrivateNetwork=yes",
		"RestrictAddressFamilies=AF_UNIX", "LoadCredential=key:",
	)

	notify := read(t, "gitoversight-notify.service")
	requireContains(t, notify,
		"User=gitoversight-notify", "Group=gitoversight-notify",
		"SupplementaryGroups=gitoversight-notifications", "ReadWritePaths=/run/gitoversight-notifications /var/lib/gitoversight-notify",
		"LoadCredential=notification-token:", "NoNewPrivileges=yes", "UMask=0077",
	)
	if strings.Contains(notify, "/var/lib/gitoversight-api") || strings.Contains(notify, "gitoversight-state") {
		t.Fatal("optional notifier must not have direct authority database access")
	}
}

func TestSystemdCredentialConsumersUseTheFullUnitDirectory(t *testing.T) {
	t.Parallel()

	checkpoint := read(t, "gitoversight-checkpoint.service")
	requireContains(t, checkpoint, "-key-file /run/credentials/gitoversight-checkpoint.service/key")

	apiConfig, err := os.ReadFile("../../config/api.example.json")
	if err != nil {
		t.Fatal(err)
	}
	workerConfig, err := os.ReadFile("../../config/worker.example.json")
	if err != nil {
		t.Fatal(err)
	}
	notifyConfig, err := os.ReadFile("../../config/notify.example.json")
	if err != nil {
		t.Fatal(err)
	}
	requireContains(t, string(apiConfig), "/run/credentials/gitoversight-api.service/webhook-secret")
	requireContains(t, string(workerConfig),
		"/run/credentials/gitoversight-worker.service/github-app-client-secret",
		"/run/credentials/gitoversight-worker.service/github-app-private-key",
		"/run/credentials/gitoversight-worker.service/vault-key",
	)
	requireContains(t, string(notifyConfig), "/run/credentials/gitoversight-notify.service/notification-token")
}

func TestEC2AccountAndDirectoryOwnershipIsExplicit(t *testing.T) {
	t.Parallel()
	sysusers := read(t, "sysusers.conf")
	for _, account := range []string{"gitoversight-api", "gitoversight-worker", "gitoversight-checkpoint", "gitoversight-notify"} {
		requireContains(t, sysusers, "u "+account+" -")
	}
	tmpfiles := read(t, "tmpfiles.conf")
	requireContains(t, tmpfiles,
		"d /run/gitoversight-authority 0750 gitoversight-api gitoversight-authority",
		"d /run/gitoversight-notifications 0750 gitoversight-api gitoversight-notifications",
		"d /var/lib/gitoversight-api 2770 gitoversight-api gitoversight-state",
		"d /var/lib/gitoversight-worker 0700 gitoversight-worker gitoversight-worker",
		"d /var/lib/gitoversight-checkpoint 0700 gitoversight-checkpoint gitoversight-checkpoint",
		"d /var/lib/gitoversight-notify 0700 gitoversight-notify gitoversight-notify",
		"d /etc/gitoversight-secrets 0700 root root",
	)
}

func TestCaddyIsTheOnlyPublicListenerAndPreservesSignedTarget(t *testing.T) {
	t.Parallel()
	caddy := read(t, "Caddyfile")
	requireContains(t, caddy,
		"{$GITOVERSIGHT_DOMAIN}", "reverse_proxy 127.0.0.1:17445",
		"header_up Host {http.request.host}", "header_up -Forwarded",
		"header_up -X-Forwarded-Host", "header_up -X-Forwarded-Proto",
	)
	if strings.Contains(caddy, "request_body") {
		t.Fatal("reference Caddyfile must remain compatible with the Ubuntu 24.04 Caddy package")
	}
	api := read(t, "gitoversight-api.service")
	requireContains(t, api, "-listen 127.0.0.1:17445")
	if strings.Contains(api, "0.0.0.0") || strings.Contains(api, ":443") {
		t.Fatal("API must remain loopback-only behind Caddy")
	}
}

func TestNginxEdgePreservesSignedTargetAndClearsForwardingAmbiguity(t *testing.T) {
	t.Parallel()
	nginx := read(t, "nginx.conf.template")
	requireContains(t, nginx,
		"server_name __GITOVERSIGHT_DOMAIN__;",
		"client_max_body_size 42m;",
		"proxy_pass http://127.0.0.1:17445;",
		"proxy_set_header Host $host;",
		"proxy_set_header Forwarded \"\";",
		"proxy_set_header X-Forwarded-For \"\";",
		"proxy_set_header X-Forwarded-Host \"\";",
		"proxy_set_header X-Forwarded-Proto \"\";",
		"proxy_set_header X-Original-Host \"\";",
		"proxy_set_header X-Original-URL \"\";",
		"ssl_certificate /etc/letsencrypt/live/__GITOVERSIGHT_DOMAIN__/fullchain.pem;",
		"ssl_certificate_key /etc/letsencrypt/live/__GITOVERSIGHT_DOMAIN__/privkey.pem;",
	)
	if strings.Contains(nginx, "0.0.0.0:17445") {
		t.Fatal("Nginx must proxy only to the loopback API")
	}
}

func TestNginxEdgeInstallerValidatesObtainsTestsAndReloads(t *testing.T) {
	t.Parallel()
	installer := read(t, "install-nginx-edge.sh")
	requireContains(t, installer,
		"install-nginx-edge.sh DOMAIN EMAIL",
		"domain_re='",
		"certbot certonly --nginx --non-interactive --agree-tos",
		"nginx -t",
		"systemctl reload nginx",
		"/etc/nginx/sites-available/gitoversight",
		"/etc/nginx/sites-enabled/gitoversight",
		"nginx.conf.template",
	)
	if strings.Contains(installer, "eval ") || strings.Contains(installer, "sed -i") {
		t.Fatal("edge installer must not evaluate inputs or edit an active config in place")
	}
}

func TestDeploymentHasNoTunnelOrPollingDependency(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("../../deploy")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name()), "tunnel") {
			t.Fatalf("legacy tunnel deployment remains: %s", entry.Name())
		}
	}
	payloads := []string{read(t, "cloud-init.yaml"), read(t, "README.md"), read(t, "Caddyfile")}
	for _, payload := range payloads {
		lower := strings.ToLower(payload)
		for _, forbidden := range []string{"cloudflared", "cloudflare tunnel", "tailscale", "poll github"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("deployment contains forbidden dependency %q", forbidden)
			}
		}
	}
}

func TestBackupAndRestoreAreConsistentEncryptedAndValidated(t *testing.T) {
	t.Parallel()
	backup := read(t, "backup.sh")
	requireContains(t, backup,
		".backup", "PRAGMA integrity_check", "--sse aws:kms",
		"GITOVERSIGHT_EDGE_MODE", "systemctl stop caddy.service", "install -m 0644 /dev/null \"$maintenance_marker\"", "state = 'executing'", "backup refused: execution drain timed out",
		"systemctl stop gitoversight-api.service", "systemctl start gitoversight-api.service",
		"GITOVERSIGHT_BACKUP_PARENT", "workdir=$(mktemp -d \"$backup_parent/backup.XXXXXX\")",
		"sha256sum gitoversight.db > gitoversight.db.sha256",
		"sha256sum checkpoint.json > checkpoint.json.sha256",
		"sha256sum gitoversight-backup.tar.gz > gitoversight-backup.tar.gz.sha256",
	)
	nginx := read(t, "nginx.conf.template")
	requireContains(t, nginx, "if (-f /run/gitoversight-maintenance) { return 503; }")
	if strings.Contains(backup, "systemctl stop nginx") || strings.Contains(backup, "systemctl start nginx") {
		t.Fatal("broker backup must never stop or start the shared Nginx service")
	}
	restore := read(t, "restore.sh")
	requireContains(t, restore,
		"PRAGMA integrity_check", "PRAGMA user_version", "restore-validation",
		"validation_root=$(mktemp -d \"$validation_parent/restore.XXXXXX\")",
		"archive=\"$validation_root/gitoversight-backup.tar.gz\"",
		"sha256sum -c gitoversight-backup.tar.gz.sha256",
		"sha256sum -c gitoversight.db.sha256",
		"sha256sum -c checkpoint.json.sha256",
		"GITOVERSIGHT_EXPECTED_TENANT", "GITOVERSIGHT_EXPECTED_POLICY_GENERATION",
		"LAG(event_hash,1,'GENESIS')", "jq -r .tail", "jq -r .policy_generation",
		"gitoversight-restore-verify", "-checkpoint-key", "-tenant",
	)
	if strings.Contains(restore, "sed -i") || strings.Contains(restore, "rm -rf") {
		t.Fatal("restore must neither rewrite checksum paths nor recursively delete an operator-supplied path")
	}
}

func TestBackupRestoreRoundTripExecutesWithPortableObjectStoreContract(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(bin, "sqlite3"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "${3:-}" == .backup* ]]; then
  target=${3#*.backup }
  target=${target#\'}
  target=${target%\'}
  cp "$1" "$target"
  exit 0
fi
case "${2:-}" in
  *integrity_check*) echo ok ;;
  *user_version*) echo 11 ;;
  *"state = 'executing'"*) echo 0 ;;
  *"COUNT(*) FROM tenants"*) echo 1 ;;
  *"MAX(generation)"*) echo 1 ;;
  *"event_hash FROM audit_events"*) echo tail-hash ;;
  *"LAG(event_hash"*) echo 0 ;;
  *) echo "unexpected sqlite query: ${2:-}" >&2; exit 1 ;;
esac
`)
	writeExecutable(t, filepath.Join(bin, "systemctl"), `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == stop || "$1" == start ]]
[[ "$2" == gitoversight-api.service || "$2" == caddy.service ]]
`)
	writeExecutable(t, filepath.Join(bin, "gitoversight-restore-verify"), `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -database && "$3" == -checkpoint-state && "$5" == -checkpoint-key && "$7" == -tenant ]]
test -f "$2"
test -f "$4"
test -f "$6"
[[ "$8" == tenant-a ]]
`)
	writeExecutable(t, filepath.Join(bin, "aws"), `#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == s3 && "$2" == cp ]]
map_path() {
  if [[ "$1" == s3://* ]]; then
    printf '%s/%s' "$FAKE_S3_ROOT" "${1#s3://}"
  else
    printf '%s' "$1"
  fi
}
source_path=$(map_path "$3")
destination_path=$(map_path "$4")
mkdir -p "$(dirname "$destination_path")"
cp "$source_path" "$destination_path"
`)
	database := filepath.Join(root, "gitoversight.db")
	checkpoint := filepath.Join(root, "checkpoint.json")
	if err := os.WriteFile(database, []byte("portable-sqlite-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkpoint, []byte(`{"tail":"tail-hash","policy_generation":1,"signature":"signed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	objectRoot := filepath.Join(root, "objects")
	backupParent := filepath.Join(root, "backup-work")
	backup := exec.Command("bash", filepath.Join(deployRoot, "backup.sh"), "s3://test-bucket/backups")
	maintenanceMarker := filepath.Join(root, "gitoversight-maintenance")
	backup.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"), "FAKE_S3_ROOT="+objectRoot,
		"GITOVERSIGHT_DATABASE="+database, "GITOVERSIGHT_CHECKPOINT_STATE="+checkpoint,
		"GITOVERSIGHT_BACKUP_PARENT="+backupParent, "GITOVERSIGHT_BACKUP_KMS_KEY=test-key",
		"GITOVERSIGHT_EDGE_MODE=nginx", "GITOVERSIGHT_MAINTENANCE_MARKER="+maintenanceMarker,
	)
	output, err := backup.CombinedOutput()
	if err != nil {
		t.Fatalf("backup: %v\n%s", err, output)
	}
	if _, err := os.Stat(maintenanceMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Nginx maintenance marker survived backup: %v", err)
	}
	uri := strings.TrimSpace(string(output))
	if !strings.HasPrefix(uri, "s3://test-bucket/backups/") || !strings.HasSuffix(uri, ".tar.gz") {
		t.Fatalf("backup uri = %q", uri)
	}

	restoreParent := filepath.Join(root, "restore-work")
	restore := exec.Command("bash", filepath.Join(deployRoot, "restore.sh"), uri)
	restore.Env = append(os.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"), "FAKE_S3_ROOT="+objectRoot,
		"GITOVERSIGHT_RESTORE_PARENT="+restoreParent, "GITOVERSIGHT_SCHEMA_VERSION=11",
		"GITOVERSIGHT_CHECKPOINT_KEY="+checkpoint,
		"GITOVERSIGHT_RESTORE_VERIFIER="+filepath.Join(bin, "gitoversight-restore-verify"),
		"GITOVERSIGHT_EXPECTED_TENANT=tenant-a", "GITOVERSIGHT_EXPECTED_POLICY_GENERATION=1",
	)
	if output, err := restore.CombinedOutput(); err != nil {
		t.Fatalf("restore: %v\n%s", err, output)
	}
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestCloudInitPinsArtifactAndFetchesSecretsFromEncryptedParameters(t *testing.T) {
	t.Parallel()
	payload := read(t, "cloud-init.yaml")
	requireContains(t, payload,
		"ARTIFACT_SHA256=", "sha256sum -c -", "--with-decryption",
		"GITHUB_APP_PRIVATE_KEY_PARAMETER=", "WEBHOOK_SECRET_PARAMETER=",
		"VAULT_KEY_PARAMETER=", "CHECKPOINT_KEY_PARAMETER=", "/readyz", "for attempt in",
	)
	if strings.Contains(payload, "curl --fail --silent http://127.0.0.1:17445/livez") {
		t.Fatal("cloud-init must not declare deployment success from liveness alone")
	}
	if strings.Contains(payload, "BEGIN PRIVATE KEY") || strings.Contains(payload, "github-app-client.secret=") {
		t.Fatal("cloud-init must contain parameter names, never secret bytes")
	}
	installer := read(t, "install.sh")
	requireContains(t, installer, "systemd-sysusers", "systemd-tmpfiles --create", "config/runtime", "id -u gitoversight-api", "id -u gitoversight-worker", "id -u gitoversight-notify", ".broker_uid = $uid", ".worker_uid = $worker_uid", ".notification_uid = $notification_uid", "GITOVERSIGHT_EDGE", "EnvironmentFile=/etc/gitoversight/caddy.env")
	if !strings.Contains(installer, `""|nginx)`) || !strings.Contains(installer, "[ -f /etc/gitoversight/install.env ]") {
		t.Fatal("installer must leave an existing shared Nginx edge untouched when no dedicated-host install environment exists")
	}
	if strings.Index(installer, `install -D -m 0644 /usr/share/gitoversight/Caddyfile /etc/caddy/Caddyfile`) < strings.Index(installer, `caddy)`) {
		t.Fatal("installer must write the live Caddy configuration only inside the selected Caddy edge branch")
	}
	if !strings.Contains(payload, "GITOVERSIGHT_EDGE=caddy") {
		t.Fatal("dedicated-host cloud-init must explicitly select Caddy")
	}
	packager := read(t, "package.sh")
	requireContains(t, packager,
		"CGO_ENABLED=0 GOOS=linux", "-trimpath", "-buildid=", "--sort=name", "SOURCE_DATE_EPOCH", "sha256sum",
		"nginx.conf.template", "install-nginx-edge.sh",
	)
	if strings.Contains(packager, `"$runtime_config"/*.json`) {
		t.Fatal("packager copies undeclared JSON files from the private runtime directory")
	}
}
