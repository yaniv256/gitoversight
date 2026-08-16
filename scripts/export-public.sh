#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: export-public.sh [options]

Build a deterministic, sanitized public-source projection. This command never
publishes, syncs, releases, or deploys.

Options:
  --source DIR                     Source repository (default: repository root)
  --allowlist FILE                 Public export allowlist
  --private-attribution-file FILE  Required private attribution EREs, one per line
  --output DIR                     Create the exported tree at a new directory
  --dry-run                        Validate and print the deterministic manifest
  --help                           Show this help
EOF
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_root=$(cd "$script_dir/.." && pwd)
allowlist=""
attribution_file=""
output=""
dry_run=false

while (($#)); do
  case "$1" in
    --source)
      (($# >= 2)) || { echo "--source requires a value" >&2; exit 2; }
      source_root=$2
      shift 2
      ;;
    --allowlist)
      (($# >= 2)) || { echo "--allowlist requires a value" >&2; exit 2; }
      allowlist=$2
      shift 2
      ;;
    --private-attribution-file)
      (($# >= 2)) || { echo "--private-attribution-file requires a value" >&2; exit 2; }
      attribution_file=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || { echo "--output requires a value" >&2; exit 2; }
      output=$2
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

source_root=$(cd "$source_root" && pwd)
if [[ -z "$allowlist" ]]; then
  allowlist="$source_root/config/public-export.allowlist"
fi
[[ -f "$allowlist" ]] || { echo "allowlist not found: $allowlist" >&2; exit 2; }
[[ -n "$attribution_file" && -f "$attribution_file" ]] || {
  echo "--private-attribution-file is required and must name a readable file" >&2
  exit 2
}
if [[ "$dry_run" == false && -z "$output" ]]; then
  echo "either --dry-run or --output is required" >&2
  exit 2
fi
if [[ -n "$output" && -e "$output" ]]; then
  echo "output must not already exist: $output" >&2
  exit 2
fi

work=$(mktemp -d)
staging="$work/export"
paths_file="$work/paths"
mkdir -p "$staging"
cleanup() {
  find "$work" -depth -mindepth 1 -delete
  rmdir "$work"
}
trap cleanup EXIT

deny_path() {
  case "$1" in
    investigations/*|docs/plans/*|docs/investigations/*|docs/acceptance/*|docs/evidence/*|docs/solutions/*|docs/superpowers/*|docs/verification/*|docs/design/*|marketing/*|cmd/gitoversight-work-probe/*|plugins/gitoversight-probe/*|plugins/gitoversight/package_test.go|scripts/tests/*|internal/contracts/contracts_test.go|internal/contracts/schema_test.go|internal/deploy/*|tests/security/work_oauth_deployment_test.go)
      return 0
      ;;
  esac
  return 1
}

validate_relative_path() {
  local value=$1
  [[ -n "$value" && "$value" != /* && "$value" != "." && "$value" != ".." && "$value" != ../* && "$value" != */../* && "$value" != */.. && "$value" != *//* && "$value" != *\\* && "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]]
}

validate_tree_paths() {
  local root=$1 found relative
  while IFS= read -r -d '' found; do
    relative=${found#"$source_root/"}
    validate_relative_path "$relative" || return 1
  done < <(find "$root" \( -type f -o -type l \) -print0)
}

: >"$paths_file"
while IFS= read -r entry || [[ -n "$entry" ]]; do
  entry=${entry%$'\r'}
  [[ -z "$entry" || "$entry" == \#* ]] && continue
  validate_relative_path "$entry" || { echo "unsafe allowlist entry: $entry" >&2; exit 1; }
  candidate="$source_root/$entry"
  [[ -e "$candidate" ]] || { echo "allowlisted path does not exist: $entry" >&2; exit 1; }
  if [[ -L "$candidate" ]]; then
    echo "allowlisted symlink is not permitted: $entry" >&2
    exit 1
  elif [[ -d "$candidate" ]]; then
    validate_tree_paths "$candidate" || { echo "allowlisted tree contains an unsafe path: $entry" >&2; exit 1; }
    if find "$candidate" -type l -print -quit | grep -q .; then
      echo "allowlisted tree contains a symlink: $entry" >&2
      exit 1
    fi
    find "$candidate" -type f -print
  elif [[ -f "$candidate" ]]; then
    printf '%s\n' "$candidate"
  else
    echo "allowlisted path is not a regular file or directory: $entry" >&2
    exit 1
  fi
done <"$allowlist" |
  while IFS= read -r absolute; do
    relative=${absolute#"$source_root/"}
    [[ "$relative" != "$absolute" ]] || { echo "path escaped source: $absolute" >&2; exit 1; }
    validate_relative_path "$relative" || { echo "unsafe export path: $relative" >&2; exit 1; }
    deny_path "$relative" && continue
    printf '%s\n' "$relative"
  done |
  LC_ALL=C sort -u >"$paths_file"

[[ -s "$paths_file" ]] || { echo "allowlist selected no files" >&2; exit 1; }

# Build sensitive markers in pieces so the exporter can scan its own source
# without embedding the complete forbidden values it detects.
pat_prefix='github_''pat_'
gh_prefix='gh''[pousr]_'
home_prefix='/home/''agent-'
secret_pattern="${pat_prefix}[A-Za-z0-9_]{40,}|${gh_prefix}[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{20,}"

scan_content() {
  local relative=$1 file=$2 pattern
  if [[ -s "$file" ]] && ! LC_ALL=C grep -Iq . "$file"; then
    echo "binary content is not permitted in public source: $relative" >&2
    return 1
  fi
  if LC_ALL=C grep -Eq "$secret_pattern" "$file"; then
    echo "secret-like content rejected: $relative" >&2
    return 1
  fi
  if LC_ALL=C grep -Fq "$home_prefix" "$file"; then
    echo "private absolute path rejected: $relative" >&2
    return 1
  fi
  while IFS= read -r pattern || [[ -n "$pattern" ]]; do
    pattern=${pattern%$'\r'}
    [[ -z "$pattern" || "$pattern" == \#* ]] && continue
    if LC_ALL=C grep -Eq "$pattern" "$file"; then
      echo "private attribution rejected: $relative" >&2
      return 1
    else
      status=$?
      if ((status == 2)); then
        echo "invalid private attribution pattern" >&2
        return 1
      fi
    fi
  done <"$attribution_file"
}

while IFS= read -r relative; do
  source_file="$source_root/$relative"
  scan_content "$relative" "$source_file"
  mode=0644
  [[ -x "$source_file" ]] && mode=0755
  install -D -m "$mode" "$source_file" "$staging/$relative"
done <"$paths_file"

manifest="$staging/PUBLIC-MANIFEST.sha256"
while IFS= read -r relative; do
  hash=$(sha256sum "$staging/$relative")
  printf '%s  %s\n' "${hash%% *}" "$relative"
done <"$paths_file" >"$manifest"

epoch=${SOURCE_DATE_EPOCH:-0}
[[ "$epoch" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2; exit 2; }
while IFS= read -r relative; do
  touch -d "@$epoch" "$staging/$relative"
done <"$paths_file"
touch -d "@$epoch" "$manifest"
find "$staging" -depth -type d -exec touch -d "@$epoch" {} +

if [[ "$dry_run" == true ]]; then
  cat "$manifest"
fi
if [[ -n "$output" ]]; then
  mkdir -p "$output"
  cp -a "$staging/." "$output/"
fi
