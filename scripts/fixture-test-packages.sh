#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# Print the Go package of every Go file that only builds under the
# test_fixtures tag, test file or not. CI runs `go test -tags=test_fixtures` on
# these packages (gibson#1227). The list comes from the files, so a new
# fixture file joins the run with no edit here. A package whose fixture code
# has no test still builds under the tag, and its tests of the plain build
# also run under the tag. The script fails when it finds no package, because
# an empty list would make the CI job pass with nothing run.
#
# Usage: fixture-test-packages.sh [root]   (root defaults to the repo root)
#        fixture-test-packages.sh --selftest
set -euo pipefail

list() {
  local root="$1"
  # A positive tag line only. `!test_fixtures` stub tests must not match.
  grep -rlE --include='*.go' '^//go:build (.* )?test_fixtures( .*)?$' "$root" \
    | grep -v '/vendor/' \
    | grep -v '^$' \
    | xargs -r -n1 dirname \
    | sort -u \
    | sed -E "s#^${root%/}#.#"
}

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/a" "$tmp/b"
  printf '//go:build test_fixtures\n\npackage a\n' > "$tmp/a/x_test.go"
  printf '//go:build !test_fixtures\n\npackage b\n' > "$tmp/b/y_test.go"
  printf '//go:build test_fixtures\n\npackage c\n' > "$tmp/c.go"
  mkdir -p "$tmp/d" "$tmp/empty"
  printf '//go:build test_fixtures\n\npackage d\n' > "$tmp/d/helper.go"
  got="$(list "$tmp" | tr '\n' ' ')"
  if [ "$got" != "./a ./d . " ] && [ "$got" != ". ./a ./d " ]; then
    echo "selftest FAILED: want ./a ./d and ., got: $got" >&2
    exit 1
  fi
  # The floor: a tree with no fixture file is an error, not an empty list.
  if "$0" "$tmp/empty" >/dev/null 2>&1; then
    echo "selftest FAILED: an empty tree passed the floor" >&2
    exit 1
  fi
  echo "fixture-test-packages selftest PASSED"
  exit 0
fi

root="${1:-.}"
root="$(cd "$root" && pwd)"
pkgs="$(list "$root" || true)"
if [ -z "$pkgs" ]; then
  echo "fixture-test-packages: no Go file under $root has a test_fixtures build tag." >&2
  echo "The fixture-tests job would run nothing. Fix the search or delete the job." >&2
  exit 1
fi
printf '%s\n' "$pkgs"
