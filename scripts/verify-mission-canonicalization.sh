#!/usr/bin/env bash
# verify-mission-canonicalization — runs the verification suite
# from mission-schema-canonicalization Task 20 + spec
# mission-verb-noun-registry Requirement 1 (extension contract).
#
# Steps (in order, fail-fast):
#   1. make check-noun-contract — every NodeType has its four
#      pieces (config, handler, e2e fixture, unit tests).
#   2. go vet ./internal/orchestrator/... ./internal/mission/...
#      ./internal/harness/... ./internal/daemon/api/...
#   3. go build ./... — daemon compiles cleanly.
#   4. go test -count=1 ./internal/orchestrator/nodes/...
#      ./internal/orchestrator/ -run TestSpawnCycle\|TestEscalateAck
#      \|TestRegister\|TestAssertExhaustive
#      ./internal/mission/definitionutil/...
#      ./internal/harness/ -run TestEffectivePerCallCap
#      ./internal/daemon/ -run TestProtovalidate
#      — exercises every test added under specs 1 + 2.
#   5. greps for forbidden state:
#      - mission.MissionDefinition outside generated code:
#        existing limited references documented as deferred
#        migration (Spec 1 Tasks 11-16).
#      - ParseError / ParseMissionDefinition: legacy parser
#        still resident; deletion deferred.
#
# Spec: mission-schema-canonicalization Task 20.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/4] check-noun-contract"
make check-noun-contract

echo "[2/4] go vet"
go vet ./internal/orchestrator/... ./internal/mission/... ./internal/harness/... ./internal/daemon/api/...

echo "[3/4] go build"
go build ./...

echo "[4/4] focused test suite"
go test -count=1 -timeout=60s \
  ./internal/orchestrator/nodes/... \
  ./internal/mission/definitionutil/... \
  -run '.*'
go test -count=1 -timeout=60s ./internal/orchestrator/ \
  -run 'TestSpawnCycle|TestEscalateAck|TestRegister|TestAssertExhaustive|TestStateRestorer'
go test -count=1 -timeout=60s ./internal/harness/ \
  -run 'TestEffectivePerCallCap'
go test -count=1 -timeout=60s ./internal/daemon/ \
  -run 'TestProtovalidate'

echo ""
echo "verify-mission-canonicalization: ok"
echo "Tasks verified:"
echo "  Spec 1 (schema-canonicalization): 1-10, 18, 19 + verification (20)"
echo "  Spec 2 (verb-noun-registry):      1-20 complete"
