#!/usr/bin/env bash
# Post-deploy smoke: EXERCISE the feature, do not merely inspect the artifact.
#
# On 2026-07-26 a deploy passed every check we had — matching checksums, /readyz
# ready, new symbols present in the running binary, 51 green test packages — and
# the feature had a 0% success rate and always had. Every one of those checks
# measures a property of the ARTIFACT. None of them invokes the product.
#
# The rule this encodes: a deploy is not verified until a real request has
# travelled the real path against the deployed system. Run this after every
# deploy. A deploy whose smoke fails is not deployed; roll back.
#
# Usage: smoke.sh [ORIGIN]   (default https://gitoversight.com)
set -uo pipefail

origin=${1:-https://gitoversight.com}
failures=0

check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then
    printf '  ok    %-46s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-46s got %s want %s\n' "$1" "$3" "$2"
    failures=$((failures + 1))
  fi
}

echo "smoke: $origin"

# --- Liveness. Necessary, nowhere near sufficient. ---
check "livez" 200 "$(curl -fsS -o /dev/null -w '%{http_code}' "$origin/livez" || echo 000)"
check "readyz ready" true "$(curl -fsS "$origin/readyz" 2>/dev/null | sed -n 's/.*"ready":\([a-z]*\).*/\1/p')"

# --- Real request paths. These would have caught the 2026-07-26 incident. ---

# An unauthenticated UI request must reach the login flow, not 5xx and not a
# blank 200. This is the route a human actually starts from.
check "ui/now redirects to login" 302 \
  "$(curl -fsS -o /dev/null -w '%{http_code}' "$origin/ui/now" || echo 000)"

# The login callback must never terminate the journey. It used to answer with
# "GitHub authorization complete. You may close this window." — a wall with no
# link, which a human reached mid-authorization and read as success.
callback_body=$(curl -sS "$origin/oauth/github/callback?state=smoke&code=smoke" 2>/dev/null || true)
if printf '%s' "$callback_body" | grep -qi 'may close this window'; then
  echo "  FAIL  oauth callback is a dead end (no way back into the app)"
  failures=$((failures + 1))
else
  echo "  ok    oauth callback is not a dead end"
fi

# The human API must REJECT an unauthenticated mutation, and must do so with an
# auth status — not 404 (route missing) and not 5xx (handler broken). A 404 here
# would mean the endpoint the UI posts to does not exist.
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -d '{}' \
  "$origin/v1/human/sync/smoke-nonexistent/authorize" 2>/dev/null || echo 000)
case "$status" in
  401|403) echo "  ok    human authorize rejects unauthenticated  $status" ;;
  *)       echo "  FAIL  human authorize returned $status, want 401/403"
           failures=$((failures + 1)) ;;
esac

# Static assets the UI cannot function without. app.js carries the entire error
# and recovery path; if it 404s, every failure becomes silent.
for asset in /ui/static/styles.css /ui/static/app.js; do
  check "asset $asset" 200 "$(curl -fsS -o /dev/null -w '%{http_code}' "$origin$asset" || echo 000)"
done

# app.js must still carry the step-up recovery. A deploy that drops it puts the
# reviewer back in the dead state with no route out.
if curl -fsS "$origin/ui/static/app.js" 2>/dev/null | grep -q 'return_to='; then
  echo "  ok    app.js carries the step-up return path"
else
  echo "  FAIL  app.js lost the step-up return path — 403 becomes a dead end again"
  failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "smoke: PASS"
  echo
  echo "NOTE: this proves the paths RESPOND. It does not prove a pre-PR can be"
  echo "published — that needs an authenticated session and a real proposal."
  echo "Before reporting a deploy complete, submit one and confirm the PR exists"
  echo "on GitHub. Green here is necessary, not sufficient."
  exit 0
fi
echo "smoke: FAIL ($failures) — the deploy is NOT verified; roll back or fix."
exit 1
