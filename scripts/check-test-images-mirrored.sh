#!/usr/bin/env bash
# check-test-images-mirrored.sh — CI guard: a Go test pulls its container
# images from the org mirror, never from Docker Hub.
#
# History: on 2026-09-18 the coverage gate on gibson#140 failed before a
# single assertion ran. TestNewPgxPool_Integration asked Docker Hub for
# postgres:16-alpine and the token request timed out. The PR touched a
# different package. Docker Hub is rate limited and outside our control.
# The org mirrors every upstream image it depends on to
# ghcr.io/zeroroot-ai/mirror (zeroroot-ai/.github mirror-list.yaml), and the
# e2e workflows pull from there already. The unit lane does the same now.
#
# The rule: every `Image:` string in a testcontainers.ContainerRequest under a
# *_test.go file starts with ghcr.io/zeroroot-ai/mirror/. Images built by
# this org (ghcr.io/zeroroot-ai/<name>) are also ours and pass.
#
# Usage:
#   scripts/check-test-images-mirrored.sh             scan the tree, exit 1 on a Docker Hub pull
#   scripts/check-test-images-mirrored.sh --selftest  prove a bare "postgres:16-alpine" fails
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Only a testcontainers request pulls an image. A CRD fixture or a sandbox
# spec with an Image field never reaches a registry, so the scan looks only
# at test files that build a testcontainers.ContainerRequest.
scan() { # dir -> prints offending file:line: image
  local dir=$1
  grep -rlE --include='*_test.go' 'testcontainers\.ContainerRequest' "$dir" 2>/dev/null \
    | xargs -r grep -nE '^\s*Image:\s*"[^"]+"' \
    | grep -vE 'Image:\s*"ghcr\.io/zeroroot-ai/' || true
}

if [[ "${1:-}" == "--selftest" ]]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  cat > "$tmp/bad_test.go" <<'GO'
package x
var r = testcontainers.ContainerRequest{
	Image:        "postgres:16-alpine",
}
GO
  cat > "$tmp/good_test.go" <<'GO'
package x
var r = testcontainers.ContainerRequest{
	Image:        "ghcr.io/zeroroot-ai/mirror/postgres:16.4-alpine",
}
var s = testcontainers.ContainerRequest{
	Image:        "ghcr.io/zeroroot-ai/gibson-tool-runner:hello-dev",
}
GO
  # A fixture with an Image field but no testcontainers request never pulls.
  cat > "$tmp/fixture_test.go" <<'GO'
package x
var spec = SandboxSpec{
	Image: "devbox:latest",
}
GO
  got=$(scan "$tmp")
  if [[ "$got" != *bad_test.go* ]]; then
    echo "SELFTEST FAIL: a bare Docker Hub image passed: [$got]"; exit 1
  fi
  if [[ "$got" == *good_test.go* ]]; then
    echo "SELFTEST FAIL: a mirrored or org image was flagged: [$got]"; exit 1
  fi
  if [[ "$got" == *fixture_test.go* ]]; then
    echo "SELFTEST FAIL: an Image field outside a testcontainers request was flagged: [$got]"; exit 1
  fi
  echo "SELFTEST OK: a bare postgres:16-alpine fails, mirror, org and non-container images pass"
  exit 0
fi

bad=$(scan "$ROOT")
if [[ -n "$bad" ]]; then
  echo "❌ Go tests pull container images from Docker Hub. Use ghcr.io/zeroroot-ai/mirror/<name>:<tag>."
  echo "   Add a missing image to mirror-list.yaml in zeroroot-ai/.github first."
  while IFS= read -r line; do echo "   $line"; done <<<"$bad"
  exit 1
fi
echo "✓ check-test-images-mirrored: every testcontainer image comes from the org mirror"
