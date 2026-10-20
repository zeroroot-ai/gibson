#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# Fixture for scripts/lint-pagination.mjs. The guard must fail on a bad proto,
# pass on a good one, and fail on a stale baseline entry. A guard that cannot
# fail is worse than none.
set -uo pipefail
cd "$(dirname "$0")/.."
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fail() { echo "lint-pagination.test: FAIL: $1" >&2; exit 1; }

mkdir "$TMP/bad" "$TMP/good"
# The fixtures are written here, not tracked as .proto files: tests/protorules
# loads every tracked .proto and these belong to no proto root.
cat > "$TMP/bad/bad.proto" <<'PROTO'
syntax = "proto3";
package fixture.v1;

service FixtureService {
  // A read that is not named List and returns a repeated field with no paging.
  rpc FetchThings(FetchThingsRequest) returns (FetchThingsResponse);
  // A request with a limit field.
  rpc CountThings(CountThingsRequest) returns (CountThingsResponse);
}

message FetchThingsRequest { string kind = 1; }
message FetchThingsResponse { repeated string things = 1; }
message CountThingsRequest { int32 limit = 1; }
message CountThingsResponse { int32 count = 1; }
PROTO
cat > "$TMP/good/good.proto" <<'PROTO'
syntax = "proto3";
package fixture.v1;

service FixtureService {
  rpc FetchThings(FetchThingsRequest) returns (FetchThingsResponse);
  rpc Watch(FetchThingsRequest) returns (stream FetchThingsResponse);
}

message FetchThingsRequest {
  string kind = 1;
  int32 page_size = 2;
  string page_token = 3;
}
message FetchThingsResponse {
  repeated string things = 1;
  string next_page_token = 2;
}
PROTO
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

# 5. A baseline entry that the base branch did not have fails: it cannot grow.
printf 'bad.proto FetchThings\n' > "$TMP/prev"
node lint-pagination.mjs --root "$TMP/bad" --baseline "$TMP/known" --prev-baseline "$TMP/prev" >/dev/null 2>&1 && fail "a grown baseline passed"

# 6. One object with a repeated attribute is not a collection.
mkdir "$TMP/obj"
cat > "$TMP/obj/obj.proto" <<'PROTO'
syntax = "proto3";
service S { rpc DescribeThing(Req) returns (Thing); rpc GetThings(Req) returns (Things); }
message Req { string id = 1; }
message Thing { string name = 1; repeated string tags = 2; }
message Things { repeated string names = 1; }
PROTO
out="$(node lint-pagination.mjs --root "$TMP/obj" --baseline "$TMP/empty" 2>&1)" && fail "a pure collection named Get passed"
grep -q "obj.proto GetThings" <<<"$out" || fail "GetThings (all fields repeated) was not caught: $out"
grep -q "DescribeThing" <<<"$out" && fail "DescribeThing (one object) was flagged: $out"

echo "lint-pagination.test: PASS"
