#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# Print the Go package of every test file that only builds under the
# test_fixtures tag. CI runs `go test -tags=test_fixtures` on these packages
# (gibson#1227). The list comes from the files, so a new fixture test joins
# the run with no edit here.
#
# Usage: fixture-test-packages.sh [root]   (root defaults to the repo root)
#        fixture-test-packages.sh --selftest
set -euo pipefail

list() {
  local root="$1"
  # A positive tag line only. `!test_fixtures` stub tests must not match.
  grep -rlE --include='*_test.go' '^//go:build (.* )?test_fixtures( .*)?$' "$root" \
    | grep -v '/vendor/' \
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
  got="$(list "$tmp")"
  if [ "$got" != "./a" ]; then
    echo "selftest FAILED: want ./a, got: $got" >&2
    exit 1
  fi
  echo "fixture-test-packages selftest PASSED"
  exit 0
fi

root="${1:-.}"
root="$(cd "$root" && pwd)"
list "$root"
