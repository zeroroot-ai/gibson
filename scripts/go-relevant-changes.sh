#!/usr/bin/env bash
# go-relevant-changes.sh: reads the changed paths of a pull request, one per
# line, on stdin, and prints "true" when the Go gates must run, else "false".
#
# The Go gates run unless every changed path is a Markdown file. A list of
# Go-relevant paths missed each new kind of Go input: a Dockerfile that a test
# reads (gibson#16), and a catalog YAML file that go:embed compiles into the
# binary (gibson#791). Each miss let a pull request skip the tests on the PR
# lane and fail them in the merge queue. No Go test reads a Markdown file of
# the repo, so Markdown is the one kind of change that skips the gates.
set -euo pipefail
relevant=false
seen=false
while IFS= read -r path; do
  [ -z "$path" ] && continue
  seen=true
  case "$path" in
    *.md) ;;
    *) relevant=true ;;
  esac
done
# An empty diff runs the gates: no answer is safer than a skipped gate.
if [ "$seen" = false ]; then relevant=true; fi
echo "$relevant"
