#!/usr/bin/env bash
# check-plugin-modules.sh — CI guard: each plugin under plugins/ is its own Go
# module that depends on the public SDK, never on gibson.
#
# Why: the GitHub and GitLab plugins moved from the integrations repo into
# gibson/plugins/<vendor>/ (ADR-0065, gibson#790). A plugin is a component that
# a stranger could write with the SDK alone. If a plugin imports a gibson
# package, the plugin and the platform stop being separable, and the image
# build copies the plugin directory only, so the build breaks too.
#
# Each plugins/<name>/ must:
#   1. have its own go.mod, whose module path is github.com/zeroroot-ai/gibson/plugins/<name>;
#   2. have no replace directive (a replace hides the real dependency);
#   3. require no zeroroot-ai module other than github.com/zeroroot-ai/sdk;
#   4. import no github.com/zeroroot-ai package other than the SDK in any .go file.
# The Go toolchain refuses an import that go.mod does not declare, so these
# four rules leave the public SDK and the declared third-party modules only.
#
# Usage:
#   bash scripts/check-plugin-modules.sh            # real check
#   bash scripts/check-plugin-modules.sh --selftest # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail

SDK='github.com/zeroroot-ai/sdk'

check_plugin() { # $1 = plugin directory; prints one line per violation
  local dir=$1 name mod bad
  name=$(basename "$dir")
  if [ ! -f "$dir/go.mod" ]; then
    echo "$dir: no go.mod; each plugin is its own Go module"
    return
  fi
  mod=$(awk '$1 == "module" {print $2; exit}' "$dir/go.mod")
  if [ "$mod" != "github.com/zeroroot-ai/gibson/plugins/$name" ]; then
    echo "$dir/go.mod: module is \"$mod\", want github.com/zeroroot-ai/gibson/plugins/$name"
  fi
  if grep -qE '^[[:space:]]*replace([[:space:]]|\()' "$dir/go.mod"; then
    echo "$dir/go.mod: has a replace directive"
  fi
  bad=$(grep -v '^module ' "$dir/go.mod" | grep -oE 'github\.com/zeroroot-ai/[A-Za-z0-9._-]+' | grep -vxF "$SDK" | sort -u || true)
  if [ -n "$bad" ]; then
    echo "$dir/go.mod: requires $(echo "$bad" | tr '\n' ' ')- a plugin depends on the public SDK only"
  fi
  bad=$(find "$dir" -name '*.go' -print0 | xargs -0 -r grep -nE '"github\.com/zeroroot-ai/' | grep -vE "\"$SDK(/|\")" || true)
  if [ -n "$bad" ]; then
    echo "$bad" | sed 's/^/import outside the SDK: /'
  fi
}

scan() {
  local violations="" dir ROOT="${SCAN_ROOT:-plugins}"
  [ -d "$ROOT" ] || { echo "check-plugin-modules: $ROOT does not exist" >&2; return 1; }
  for dir in "$ROOT"/*/; do
    dir=${dir%/}
    violations+=$(check_plugin "$dir")
  done
  if [ -n "$violations" ]; then
    echo "$violations" | sed 's/^/::error::/'
    echo "check-plugin-modules: a plugin module reaches outside the public SDK (ADR-0065)." >&2
    return 1
  fi
  echo "check-plugin-modules: each plugin is its own module on the public SDK."
}

selftest() {
  local rc case
  tmp=$(mktemp -d); trap "rm -rf '$tmp'" EXIT
  write_plugin() { # $1 root, $2 name, $3 extra go.mod text, $4 import path
    mkdir -p "$1/$2"
    printf 'module github.com/zeroroot-ai/gibson/plugins/%s\n\ngo 1.26\n\nrequire github.com/zeroroot-ai/sdk v0.1.0\n%s\n' "$2" "$3" > "$1/$2/go.mod"
    printf 'package main\n\nimport _ "%s"\n' "$4" > "$1/$2/main.go"
  }
  # case 1: each kind of violation must be rejected.
  write_plugin "$tmp/c1" p 'replace github.com/zeroroot-ai/sdk => ../sdk' "$SDK/plugin"
  write_plugin "$tmp/c2" p 'require github.com/zeroroot-ai/setec v0.1.0' "$SDK/plugin"
  write_plugin "$tmp/c3" p '' "github.com/zeroroot-ai/gibson/internal/platform/authz"
  write_plugin "$tmp/c6" p 'require github.com/zeroroot-ai/gibson v0.1.0' "$SDK/plugin"
  write_plugin "$tmp/c4" p '' "$SDK/plugin"
  sed -i 's#plugins/p$#plugins/other#' "$tmp/c4/p/go.mod"
  mkdir -p "$tmp/c5/p"
  for case in c1 c2 c3 c4 c5 c6; do
    rc=0; SCAN_ROOT="$tmp/$case" scan >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 1 ]; then echo "SELFTEST $case FAILED: violation not rejected (rc=$rc)" >&2; return 1; fi
  done
  echo "SELFTEST case 1 PASSED: replace, foreign module, gibson module, gibson import, wrong path and no go.mod rejected."
  # case 2: a plugin on the SDK and a third-party module must pass.
  write_plugin "$tmp/good" p 'require github.com/google/go-github/v90 v90.0.0' "$SDK/plugin"
  SCAN_ROOT="$tmp/good" scan >/dev/null 2>&1 || { echo "SELFTEST case 2 FAILED: clean plugin rejected" >&2; return 1; }
  echo "SELFTEST case 2 PASSED: clean plugin accepted."
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
