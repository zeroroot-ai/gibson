#!/usr/bin/env bash
# Fixture of scripts/proto-field-consumer-roots.sh. It builds six local
# remotes and proves which ref the script reads for each consumer.
set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/proto-field-consumer-roots.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid

repos='sdk adk gibson-executor setec dashboard sdk-ts'
for r in $repos; do
  git init --quiet --initial-branch=main "$tmp/remotes/$r.git"
  echo main > "$tmp/remotes/$r.git/marker"
  git -C "$tmp/remotes/$r.git" add marker
  git -C "$tmp/remotes/$r.git" commit --quiet -m main
done
# Only the dashboard has the paired branch.
git -C "$tmp/remotes/dashboard.git" checkout --quiet -b epic/paired
echo paired > "$tmp/remotes/dashboard.git/marker"
git -C "$tmp/remotes/dashboard.git" commit --quiet -am paired
git -C "$tmp/remotes/dashboard.git" checkout --quiet main

export PROTO_CONSUMERS_REMOTE="file://$tmp/remotes"
export PROTO_CONSUMER_REF_FILE="$tmp/ref"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1"; }
marker() { cat "$1/$2/marker"; }

# 1. No ref file: each consumer is read at main.
rm -f "$tmp/ref"
roots="$(bash "$script" "$tmp/c1" 2>/dev/null)"
if [ "$(marker "$tmp/c1" dashboard)" = main ] && [ "$(marker "$tmp/c1" sdk)" = main ]; then
  ok "no ref file -> main"
else bad "no ref file -> main"; fi

# 2. The output starts with "." and names six clones.
set -- $roots
if [ "$1" = "." ] && [ "$#" -eq 7 ]; then ok "prints seven roots"; else bad "prints seven roots: $roots"; fi

# 3. A paired branch: the consumer that has it is read there, the others at main.
printf '# comment\nepic/paired\n' > "$tmp/ref"
bash "$script" "$tmp/c2" >/dev/null 2>&1
if [ "$(marker "$tmp/c2" dashboard)" = paired ] && [ "$(marker "$tmp/c2" sdk)" = main ]; then
  ok "paired branch -> the branch where it exists, main elsewhere"
else bad "paired branch -> the branch where it exists, main elsewhere"; fi

# 4. A branch that no consumer has: main, with a notice to empty the file.
echo 'epic/gone' > "$tmp/ref"
notice="$(bash "$script" "$tmp/c3" 2>&1 >/dev/null)"
if [ "$(marker "$tmp/c3" dashboard)" = main ] && grep -q 'empty' <<< "$notice"; then
  ok "branch nobody has -> main and a notice"
else bad "branch nobody has -> main and a notice"; fi

# 5. A name that is not a branch name fails.
echo '--upload-pack=x' > "$tmp/ref"
if bash "$script" "$tmp/c4" >/dev/null 2>&1; then bad "MUTATION option as a name -> fail"; else ok "MUTATION option as a name -> fail"; fi

# 6. A consumer that cannot be cloned fails the run.
rm -f "$tmp/ref"
mv "$tmp/remotes/setec.git" "$tmp/remotes/setec.gone"
if bash "$script" "$tmp/c5" >/dev/null 2>&1; then bad "MUTATION a missing consumer -> fail"; else ok "MUTATION a missing consumer -> fail"; fi

echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
