#!/usr/bin/env bash
#
# Fixture for check-proto-field-consumers.sh.
#
# Every rule gets a case that is RED for the stated reason, not merely non-zero:
# each red case asserts a substring of the message, so a rule that starts failing
# for a different reason is a test failure rather than a pass.
#
# Offline by construction. No Go module is loaded: GO_READS_FILE supplies a
# crafted type-resolved read set, and PROTO_DIR a crafted schema. The TS and
# Python halves run for real over a crafted consumer tree, because they are
# plain text scans with no toolchain behind them.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

GATE=scripts/check-proto-field-consumers.sh
PASS=0 FAIL=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# A schema with a nested message, a one-line empty message, a oneof, an enum,
# a reserved line and a commented-out field. Only real fields count.
mkdir -p "$tmp/proto/gibson/fx/v1" "$tmp/consumer/src" "$tmp/consumer/src/gen" "$tmp/consumer/py"
cat > "$tmp/proto/gibson/fx/v1/fx.proto" <<'PROTO'
syntax = "proto3";
package gibson.fx.v1;
option go_package = "example.com/fx/api/gibson/fx/v1;fxv1";

message Empty {}

enum Kind {
  KIND_UNSPECIFIED = 0;
  KIND_ONE = 1;
}

message AckResponse {
  reserved 9;
  bool acked = 1;            // read by Go
  int64 applied_at_unix = 2; // read by TS
  string note = 3;           // read by Python
  // string ghost = 7;
  message Detail {
    string reason = 1;       // read by Go through the nested type
  }
  Detail detail = 4;
  oneof which {
    string a_side = 5;       // never read
    string b_side = 6;       // read by TS only inside a comment
  }
  string only_test = 8;      // read in a test file only
  bool store_neo4j = 10;     // read by Go as StoreNeo4J (letter after a digit)
  bool neo4j_ready = 11;     // read by TS as neo4jReady (no capital after the digit)
}
PROTO
cat > "$tmp/consumer/src/app.ts" <<'TS'
export function show(r: { appliedAtUnix: number; neo4jReady: boolean }) {
  // bSide is mentioned here and nowhere else
  return r.appliedAtUnix;
}
TS
cat > "$tmp/consumer/src/gen/fx_pb.ts" <<'TS'
export class AckResponse { aSide = ""; bSide = ""; onlyTest = ""; }
TS
cat > "$tmp/consumer/src/app.test.ts" <<'TS'
expect(r.onlyTest).toBe("");
TS
cat > "$tmp/consumer/py/use.py" <<'PY'
def f(r):
    return r.note
PY

reads() { printf '%s\n' "$@"; }
GO_OK="example.com/fx/api/gibson/fx/v1.AckResponse.Acked
example.com/fx/api/gibson/fx/v1.AckResponse_Detail.Reason
example.com/fx/api/gibson/fx/v1.AckResponse.Detail
example.com/fx/api/gibson/fx/v1.AckResponse.StoreNeo4J"

# run <name> <expected rc> <expected substring> <exempt text> <go reads>
check() {
  printf '%s\n' "$4" > "$tmp/exempt"
  printf '%s\n' "$5" > "$tmp/goreads"
  out="$(PROTO_DIR="$tmp/proto" EXEMPT_FILE="$tmp/exempt" MIN_FIELDS=5 \
    GO_PREFIX="example.com/fx/api/" GO_READS_FILE="$tmp/goreads" \
    CONSUMER_ROOTS="$tmp/consumer" bash "$GATE" 2>&1)"; rc=$?
  if [ "$rc" -eq "$2" ] && [[ "$out" == *"$3"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $1 (rc=$rc)"; echo "$out" | sed 's/^/    /'; fi
}

check "the unread fields are named and the read ones are not" 1 "3 without a consumer" "" "$GO_OK"
check "a_side is dead" 1 "dead	gibson.fx.v1.AckResponse.a_side" "" "$GO_OK"
check "a TS mention inside a comment is not a read" 1 "dead	gibson.fx.v1.AckResponse.b_side" "" "$GO_OK"
check "a read in a test file is not a read" 1 "dead	gibson.fx.v1.AckResponse.only_test" "" "$GO_OK"
check "a Go read on a different type does not count" 1 "dead	gibson.fx.v1.AckResponse.acked" "" "example.com/fx/api/gibson/fx/v1.Other.Acked"
check "a letter after a digit is capitalized like protoc-gen-go does" 1 "dead	gibson.fx.v1.AckResponse.store_neo4j" "" "example.com/fx/api/gibson/fx/v1.AckResponse.StoreNeo4j"
check "a TS name keeps the letter after a digit lowercase" 1 "10 fields served, 3 without" "" "$GO_OK"
check "a nested message field is keyed Outer_Inner in Go" 1 "dead	gibson.fx.v1.AckResponse.Detail.reason" "" "example.com/fx/api/gibson/fx/v1.AckResponse.Acked"
check "a verdict with a reference clears a field" 1 "2 without a consumer, 1 verdicts" "gibson.fx.v1.AckResponse.a_side | #502 | kept until the caller lands" "$GO_OK"
check "a verdict per dead field makes the gate green" 0 "0 without a consumer, 3 verdicts" "gibson.fx.v1.AckResponse.a_side | #502 | kept
gibson.fx.v1.AckResponse.b_side | #502 | kept
gibson.fx.v1.AckResponse.only_test | #502 | kept" "$GO_OK"
check "a verdict without a reference is refused" 1 "names no issue or ADR" "gibson.fx.v1.AckResponse.a_side | because | kept" "$GO_OK"
check "a verdict for a field that now has a consumer is stale" 1 "now has a consumer" "gibson.fx.v1.AckResponse.acked | #502 | kept" "$GO_OK"
check "a verdict for a field that no longer exists is stale" 1 "is not a declared field" "gibson.fx.v1.AckResponse.gone | #502 | kept" "$GO_OK"

out="$(PROTO_DIR="$tmp/proto" EXEMPT_FILE=/dev/null MIN_FIELDS=500 GO_READS_FILE="$tmp/goreads" CONSUMER_ROOTS="$tmp/consumer" bash "$GATE" 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && [[ "$out" == *"below the floor"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: the floor fails a run that measured too little (rc=$rc)"; echo "$out" | sed 's/^/    /'; fi
out="$(PROTO_DIR="$tmp/proto" EXEMPT_FILE=/dev/null MIN_FIELDS=5 GO_READS_FILE="$tmp/goreads" CONSUMER_ROOTS="$tmp/consumer $tmp/missing" bash "$GATE" 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && [[ "$out" == *"does not exist"* ]]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: a missing consumer root fails the run (rc=$rc)"; echo "$out" | sed 's/^/    /'; fi
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
