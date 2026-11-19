#!/usr/bin/env bash
# proto-field-consumer-roots.sh: clone the six other consumers of the daemon
# protos and print CONSUMER_ROOTS for check-proto-field-consumers.sh.
#
# Usage: proto-field-consumer-roots.sh <directory for the clones>
#
# The ref of a consumer is `main`, with one exception. A change that adds a
# field together with its reader in another repo cannot pass against that repo
# at `main`: the reader is on a branch that waits for this change. For such a
# change, write the name of one branch in `.proto-consumer-ref`. A consumer
# that has a branch of that name is measured at that branch. A consumer that
# does not have it is measured at `main`. After the consumer branches merge
# and go away, each consumer is measured at `main` again, and the script
# prints a notice to empty the file.
#
# The script fails when a clone fails. A run that never looked at a consumer
# would report the fields of that consumer as dead.
set -euo pipefail

dest="${1:?usage: proto-field-consumer-roots.sh <directory for the clones>}"
consumers='sdk adk gibson-executor setec dashboard sdk-ts'

remote="${PROTO_CONSUMERS_REMOTE:-https://github.com/zeroroot-ai}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref_file="${PROTO_CONSUMER_REF_FILE:-$root/.proto-consumer-ref}"
paired=""
if [ -f "$ref_file" ]; then
  paired="$(grep -v '^#' "$ref_file" | tr -d '[:space:]' || true)"
fi
case "$paired" in
  ''|main) paired="" ;;
  -*|*..*|*[!A-Za-z0-9._/-]*)
    echo "proto-field-consumer-roots: $ref_file holds a name that is not a branch name" >&2
    exit 1 ;;
esac

mkdir -p "$dest"
out=(.)
used=0
for repo in $consumers; do
  clone="$dest/$repo"
  url="$remote/$repo.git"
  ref=main
  if [ -n "$paired" ] && git ls-remote --exit-code --heads "$url" "refs/heads/$paired" >/dev/null 2>&1; then
    ref="$paired"
    used=1
  fi
  if [ ! -d "$clone/.git" ]; then
    git init --quiet "$clone"
    git -C "$clone" remote add origin "$url"
  fi
  git -C "$clone" fetch --quiet --depth=1 origin "refs/heads/$ref"
  git -C "$clone" reset --quiet --hard FETCH_HEAD
  echo "proto-field-consumer-roots: $repo at $ref $(git -C "$clone" rev-parse --short HEAD)" >&2
  out+=("$clone")
done

if [ -n "$paired" ] && [ "$used" -eq 0 ]; then
  echo "proto-field-consumer-roots: no consumer has the branch $paired; empty $ref_file" >&2
fi

echo "${out[*]}"
