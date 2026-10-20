#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# Fixture for scripts/lint-pagination.mjs. The guard must fail on a bad proto,
# pass on a good one, and fail on a stale baseline entry. A guard that cannot
# fail is worse than none.
set -uo pipefail
cd "$(dirname "$0")/.."
FIX="__tests__/lint-pagination"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "lint-pagination.test: FAIL: $1" >&2; exit 1; }

mkdir "$TMP/bad" "$TMP/good"
cp "$FIX/bad.proto" "$TMP/bad/"
cp "$FIX/good.proto" "$TMP/good/"
: > "$TMP/empty"

# 1. A list RPC not named List*, and a limit field, both fail.
out="$(node lint-pagination.mjs --root "$TMP/bad" --baseline "$TMP/empty" 2>&1)" && fail "bad proto passed"
grep -q "bad.proto FetchThings" <<<"$out" || fail "a repeated response without paging was not caught: $out"
grep -q "bad.proto CountThings" <<<"$out" || fail "a limit field was not caught: $out"

# 2. A good proto passes, a stream is not asked to page.
node lint-pagination.mjs --root "$TMP/good" --baseline "$TMP/empty" >/dev/null 2>&1 || fail "good proto failed"

# 3. A baseline entry for an RPC that now passes is stale and fails.
echo "good.proto FetchThings" > "$TMP/stale"
node lint-pagination.mjs --root "$TMP/good" --baseline "$TMP/stale" >/dev/null 2>&1 && fail "a stale baseline entry passed"

# 4. A baselined violation passes.
printf 'bad.proto FetchThings\nbad.proto CountThings\n' > "$TMP/known"
node lint-pagination.mjs --root "$TMP/bad" --baseline "$TMP/known" >/dev/null 2>&1 || fail "a baselined violation failed"

echo "lint-pagination.test: PASS"
