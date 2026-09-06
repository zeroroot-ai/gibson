#!/usr/bin/env bash
# check-no-tracked-binaries.sh — CI guard: no compiled binary is tracked in git.
#
# Why: on 2026-09-05 the tree carried four ELF executables (92 MB) with no
# ignore rule: bootstrap-tenant-owner, gen-fga-model-json and two controller-gen
# copies under operators/tenant/bin. A public repo that ships build outputs in
# git is the first thing a reviewer flags, and a fresh history bakes them into
# commit 1 forever. Keyed by CONTENT (executable magic numbers), never by path,
# so a new binary under a new name fails the same way.
#
# Detects: ELF (\x7fELF), Mach-O (feedface, feedfacf, cafebabe, cefaedfe,
# cffaedfe), PE (MZ). Scans every file `git ls-files` reports, or every regular
# file under SCAN_ROOT when that variable is set (used by --selftest).
#
# Usage:
#   bash scripts/check-no-tracked-binaries.sh            # real check
#   bash scripts/check-no-tracked-binaries.sh --selftest # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail

magic_of() { # print the first 4 bytes of a file as lowercase hex
  head -c 4 -- "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

is_binary() {
  local f=$1 m
  [ -f "$f" ] && [ ! -L "$f" ] || return 1
  [ "$(stat -c %s -- "$f")" -ge 4 ] || return 1
  m=$(magic_of "$f")
  case "$m" in
    7f454c46) return 0 ;;                                   # ELF
    feedface|feedfacf|cafebabe|cefaedfe|cffaedfe) return 0 ;; # Mach-O
    4d5a????) return 0 ;;                                   # PE (MZ)
  esac
  return 1
}

list_files() {
  if [ -n "${SCAN_ROOT:-}" ]; then
    find "$SCAN_ROOT" -type f -print0
  else
    git ls-files -z
  fi
}

scan() {
  local violations=0 f
  while IFS= read -r -d '' f; do
    if is_binary "$f"; then
      echo "::error file=$f::tracked compiled binary ($(stat -c %s -- "$f") bytes, magic $(magic_of "$f"))"
      violations=$((violations + 1))
    fi
  done < <(list_files)
  if [ "$violations" -gt 0 ]; then
    echo "check-no-tracked-binaries: $violations tracked binary file(s). Build outputs belong in bin/ (ignored), never in git." >&2
    return 1
  fi
  echo "check-no-tracked-binaries: no tracked binaries."
}

selftest() {
  local rc
  tmp=$(mktemp -d); trap "rm -rf '$tmp'" EXIT
  # case 1: a fake ELF and a fake PE next to a text file must be rejected
  mkdir -p "$tmp/a/deep"
  printf '\x7fELF\x02\x01\x01\x00padding' > "$tmp/a/deep/tool"
  printf 'MZ\x90\x00\x03\x00\x00\x00pad' > "$tmp/a/tool.exe"
  printf 'plain text\n' > "$tmp/a/README.md"
  rc=0; SCAN_ROOT="$tmp/a" scan >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 1 ]; then echo "SELFTEST case 1 FAILED: binaries not rejected (rc=$rc)" >&2; return 1; fi
  echo "SELFTEST case 1 PASSED: ELF and PE fixtures rejected."
  # case 2: text, a symlink and a short file must pass
  mkdir -p "$tmp/b"
  printf 'package main\n' > "$tmp/b/main.go"
  printf 'ab' > "$tmp/b/short"
  ln -s /nonexistent "$tmp/b/link"
  SCAN_ROOT="$tmp/b" scan >/dev/null 2>&1 || { echo "SELFTEST case 2 FAILED: clean tree rejected" >&2; return 1; }
  echo "SELFTEST case 2 PASSED: clean tree accepted."
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
