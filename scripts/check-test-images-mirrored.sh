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
# 2026-09-25 (gibson#233 merge-queue eviction): the guard only matched a
# bare `Image: "literal"` string, so `Image: openbaoImage` — a package-level
# const holding a Docker Hub image — passed clean while the test pulled
# openbao/openbao:2.5.3 straight from Docker Hub and got rate-limited in the
# merge queue. The fix resolves an `Image:` identifier back to its const/var
# declaration anywhere in the same package (same directory) and checks the
# resolved literal. An identifier that cannot be resolved to a string
# literal, or that resolves to a non-mirror value, fails the guard: there is
# no silent pass for an unverified `Image:` value.
#
# The rule: every `Image:` value in a testcontainers.ContainerRequest under a
# *_test.go file starts with ghcr.io/zeroroot-ai/mirror/. Images built by
# this org (ghcr.io/zeroroot-ai/<name>) are also ours and pass.
#
# Usage:
#   scripts/check-test-images-mirrored.sh             scan the tree, exit 1 on a Docker Hub pull
#   scripts/check-test-images-mirrored.sh --selftest  prove the fixture cases fail/pass as expected

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# resolve_ident PKGDIR IDENT — print the string literal assigned to a
# package-level const/var named IDENT anywhere under PKGDIR (Go package =
# directory), or nothing if it cannot be resolved. Takes the first
# declaration found; a package that declares the same name twice does not
# compile, so this is unambiguous in practice.
resolve_ident() {
  local pkgdir=$1 ident=$2
  # Matches, inside a `const (...)` / `var (...)` block or on a standalone
  # `const IDENT = "..."` / `var IDENT TYPE = "..."` line, optionally
  # preceded by the const/var keyword and/or a type name before the `=`.
  grep -hoE "^[[:space:]]*(const|var)?[[:space:]]*${ident}([[:space:]]+[A-Za-z_][A-Za-z0-9_.]*)?[[:space:]]*=[[:space:]]*\"[^\"]*\"" \
    "$pkgdir"/*.go 2>/dev/null \
    | head -1 \
    | grep -oE '"[^"]*"' \
    | head -1 \
    | tr -d '"'
}

# scan DIR — prints one "file:line: image" per offending Image value.
scan() {
  local dir=$1
  local files
  files=$(grep -rlE --include='*_test.go' 'testcontainers\.ContainerRequest' "$dir" 2>/dev/null || true)
  [[ -z "$files" ]] && return 0

  local file
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    local pkgdir
    pkgdir=$(dirname "$file")

    local match
    while IFS= read -r match; do
      [[ -z "$match" ]] && continue
      local lineno rest value img
      lineno=${match%%:*}
      rest=${match#*:}
      # Strip the leading "Image:" field name and any trailing comma.
      value=$(sed -E 's/^[[:space:]]*Image:[[:space:]]*//' <<<"$rest")
      value=$(sed -E 's/,[[:space:]]*$//' <<<"$value")

      if [[ "$value" =~ ^\"([^\"]*)\"$ ]]; then
        img="${BASH_REMATCH[1]}"
      elif [[ "$value" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        img=$(resolve_ident "$pkgdir" "$value")
        if [[ -z "$img" ]]; then
          echo "${file}:${lineno}: Image: ${value} — identifier does not resolve to a string literal in this package"
          continue
        fi
      else
        echo "${file}:${lineno}: Image: ${value} — not a string literal or a resolvable identifier"
        continue
      fi

      if [[ ! "$img" =~ ^ghcr\.io/zeroroot-ai/ ]]; then
        echo "${file}:${lineno}: Image=\"${img}\""
      fi
    done < <(grep -nE '^[[:space:]]*Image:[[:space:]]*[^[:space:]]' "$file")
  done <<<"$files"
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
var s = testcontainers.ContainerRequest{
	Image:        "ghcr.io/zeroroot-ai/mirror/postgres:16.4-alpine",
}
var t = testcontainers.ContainerRequest{
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

  # gibson#233 regression case: Image is an identifier, not a literal. One
  # const resolves to a Docker Hub image (must fail), the other to a mirror
  # image (must pass). The const declarations live in a separate file in the
  # same package, same as gibson's openbao_testconsts_test.go pattern.
  cat > "$tmp/const_bad_test.go" <<'GO'
package x
var u = testcontainers.ContainerRequest{
	Image:        someHubImage,
}
GO

  cat > "$tmp/const_good_test.go" <<'GO'
package x
var v = testcontainers.ContainerRequest{
	Image:        someMirrorImage,
}
GO

  cat > "$tmp/const_defs_test.go" <<'GO'
package x

const (
	someHubImage    = "openbao/openbao:2.5.3"
	someMirrorImage = "ghcr.io/zeroroot-ai/mirror/openbao:2.5.3"
)
GO

  # An identifier that resolves to nothing in the package must fail, not
  # pass by default.
  cat > "$tmp/const_unresolved_test.go" <<'GO'
package x
var w = testcontainers.ContainerRequest{
	Image:        undeclaredImage,
}
GO

  got=$(scan "$tmp")

  fail=0
  check_present() { [[ "$got" == *"$1"* ]] || { echo "SELFTEST FAIL: expected to see '$1' in: [$got]"; fail=1; }; }
  check_absent()  { [[ "$got" != *"$1"* ]] || { echo "SELFTEST FAIL: did not expect to see '$1' in: [$got]"; fail=1; }; }

  check_present "bad_test.go"
  check_absent  "good_test.go"
  check_absent  "fixture_test.go"
  check_present "const_bad_test.go"
  check_absent  "const_good_test.go"
  check_present "const_unresolved_test.go"

  if [[ "$fail" -ne 0 ]]; then
    exit 1
  fi
  echo "SELFTEST OK: literal, mirror/org, non-container, resolvable-const and unresolvable-const cases all behave"
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
