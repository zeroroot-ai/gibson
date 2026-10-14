#!/usr/bin/env bash
# check-generated-fresh.sh: the generated files under a directory match what
# the generator just wrote.
#
# A drift gate runs the generator, then compares. `git diff --exit-code <dir>`
# sees a changed tracked file only. A NEW file that the generator writes is
# untracked, and git diff passes it (gibson#807 condition 7). This compares
# with `git status --porcelain`, which also reports untracked and deleted
# files.
#
#   check-generated-fresh.sh <dir>...    exit 1 when a file differs
#   check-generated-fresh.sh --selftest  prove each case fails
set -euo pipefail

check() {
  local out
  out="$(git status --porcelain --untracked-files=all -- "$@")"
  if [ -n "${out}" ]; then
    echo "check-generated-fresh: the generator changed these files:"
    echo "${out}" | sed 's/^/    /'
    return 1
  fi
}

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
  cd "${tmp}"
  git init -q .
  git config user.email t@t; git config user.name t
  mkdir gen; echo a > gen/a.txt; git add gen; git commit -qm base
  fails=0
  expect() { # expect <pass|fail> <desc>
    if check gen >/dev/null; then got=pass; else got=fail; fi
    if [ "${got}" = "$1" ]; then echo "  ok    $2 -> ${got}"; else echo "  FAIL  $2 -> ${got}, want $1"; fails=$((fails + 1)); fi
  }
  expect pass "nothing changed"
  echo b > gen/a.txt;  expect fail "MUTATION a tracked file changed"; git checkout -q gen/a.txt
  echo c > gen/new.txt; expect fail "MUTATION a new untracked file"; rm gen/new.txt
  rm gen/a.txt;        expect fail "MUTATION a tracked file deleted"; git checkout -q gen/a.txt
  echo "check-generated-fresh --selftest: ${fails} failure(s)"
  exit $(( fails > 0 ))
fi

[ $# -gt 0 ] || { echo "usage: $0 <dir>... | --selftest" >&2; exit 2; }
check "$@"
