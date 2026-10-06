#!/usr/bin/env bash
# lint-unwired-plugins.sh — CI guard: no plugin module under plugins/ adds a
# declaration that production code reads nowhere (gibson#956).
#
# Each plugin is its own Go module (gibson#790), so the unwired counter of
# ast-checks runs once for each module, against plugins/<name>/.unwired-baseline.txt.
# The baseline only shrinks. Each entry has a "# consumer:" line above it that
# names the reader the counter cannot see, for example the JSON marshaller of
# the SDK that reads each field of a handler response.
#
# The counter version comes from the ast-checks line of the root go.mod, so a
# Dependabot bump moves the measurer and the root module together.
#
# Usage:
#   bash scripts/lint-unwired-plugins.sh             # real check
#   bash scripts/lint-unwired-plugins.sh --selftest  # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(awk '$1=="github.com/zeroroot-ai/ast-checks"{print $2; exit}' go.mod)
case "$VERSION" in
  v*) ;;
  *) echo "lint-unwired-plugins: no ast-checks version in go.mod, so the baseline has no pinned measurer" >&2; exit 2 ;;
esac

# check_module runs the counter for one module and checks that each baseline
# entry names its consumer. It prints the problems and returns 1 on any.
check_module() { # $1 = module directory
  local dir=$1 rc=0 out
  if [ ! -f "$dir/.unwired-baseline.txt" ]; then
    echo "$dir: no .unwired-baseline.txt; write one with: (cd $dir && go run github.com/zeroroot-ai/ast-checks/cmd/unwired@$VERSION -dir . -baseline .unwired-baseline.txt -write)"
    return 1
  fi
  if ! out=$(cd "$dir" && go run "github.com/zeroroot-ai/ast-checks/cmd/unwired@$VERSION" -dir . -baseline .unwired-baseline.txt 2>&1); then
    echo "$dir: the unwired counter found a declaration that nothing reads:"
    echo "$out" | grep -v "switching to" | sed 's/^/    /'
    rc=1
  fi
  if ! awk -v f="$dir/.unwired-baseline.txt" '
      /^[a-z]+ / { if (prev !~ /^# consumer: /) { print f ": entry \"" $1 " " $2 "\" has no \"# consumer:\" line above it"; bad=1 } }
      { prev=$0 }
      END { exit bad }' "$dir/.unwired-baseline.txt"; then
    rc=1
  fi
  return $rc
}

selftest() {
  local tmp fails=0
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  # 1. A declaration that nothing reads, and that the baseline does not hold.
  cp -r plugins/github "$tmp/unread"
  printf 'package main\n\n// NotReadAnywhere is the fixture of the self-test.\nvar NotReadAnywhere = 1\n' > "$tmp/unread/selftest_unread.go"
  if check_module "$tmp/unread" >/dev/null; then echo "selftest: an unread declaration passed"; fails=1; fi
  # 2. A baseline entry with no consumer line.
  cp -r plugins/github "$tmp/noreason"
  sed -i '/^# consumer: /d' "$tmp/noreason/.unwired-baseline.txt"
  if check_module "$tmp/noreason" >/dev/null; then echo "selftest: an entry with no consumer line passed"; fails=1; fi
  # 3. A module with no baseline.
  cp -r plugins/github "$tmp/nobaseline"
  rm "$tmp/nobaseline/.unwired-baseline.txt"
  if check_module "$tmp/nobaseline" >/dev/null; then echo "selftest: a module with no baseline passed"; fails=1; fi
  # 4. The real module passes, so the three failures above have one cause each.
  if ! check_module plugins/github >/dev/null; then echo "selftest: the real github module failed"; fails=1; fi
  [ "$fails" -eq 0 ] && echo "lint-unwired-plugins: selftest passed (4 cases)"
  return $fails
}

case "${1:-}" in
  --selftest) selftest ;;
  "")
    rc=0
    for d in plugins/*/; do check_module "${d%/}" || rc=1; done
    [ "$rc" -eq 0 ] && echo "lint-unwired-plugins: each plugin module is clean"
    exit $rc ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
