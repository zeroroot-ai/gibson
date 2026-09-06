#!/usr/bin/env bash
# check-noun-contract — enforces the verb/noun extension contract from
# mission-verb-noun-registry Requirement 1, against the dispatch model the
# code ACTUALLY uses.
#
# History (gibson#1399): the first version of this guard encoded a handler
# model that was never built — per-noun packages under
# internal/orchestrator/nodes/<noun>/ registering RegisterNodeHandler(...).
# Neither the directory nor the function has ever existed in this repo, so
# the guard failed on every NodeType from the day it landed, `make check`
# was permanently red locally, and the aggregate quietly stopped being run.
# A guard that cannot pass protects nothing; this rewrite grounds each
# check in a real artifact.
#
# For every NodeType enum value in the SDK proto (excluding UNSPECIFIED):
#   (a) a <Noun>NodeConfig variant in the MissionNode config oneof;
#   (b) a `case missionv1.NodeType_<NT>:` arm in the real dispatch switch
#       (internal/engine/mission/graph/graph.go — NodeTypes dispatch via
#       switch, not a registry);
#   (c) an e2e fixture at tests/e2e/missions/<noun>.yaml;
#   (d) at least one test in the dispatch package referencing the NodeType.
#
# MISSION_PROTO_OVERRIDE and DISPATCH_FILE_OVERRIDE exist so the guard can
# be mutation-tested against doctored copies (a new enum value with no
# dispatch arm MUST fail); they are test seams, not configuration.
#
# Spec: mission-verb-noun-registry Requirement 1.

set -euo pipefail

DISPATCH_FILE="${DISPATCH_FILE_OVERRIDE:-internal/engine/mission/graph/graph.go}"
# The test dir deliberately does NOT follow DISPATCH_FILE_OVERRIDE: the
# override exists to mutation-test the dispatch-arm check in isolation, and
# letting it drag check (d) to a doctored directory would make that check
# fail for a side-effect reason instead of its own.
DISPATCH_TEST_DIR="internal/engine/mission/graph"

if [ -n "${MISSION_PROTO_OVERRIDE:-}" ]; then
  MISSION_PROTO="${MISSION_PROTO_OVERRIDE}"
else
  SDK_PROTO_DIR="$(go list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk 2>/dev/null || true)"
  if [ -z "${SDK_PROTO_DIR}" ] || [ ! -d "${SDK_PROTO_DIR}" ]; then
    # A cold module cache resolves to nothing (bit the sdk-bump PR's CI job,
    # which runs no build before this guard). Download just the one module
    # and retry rather than failing on cache state.
    go mod download github.com/zeroroot-ai/sdk >/dev/null 2>&1 || true
    SDK_PROTO_DIR="$(go list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk 2>/dev/null || true)"
  fi
  if [ -z "${SDK_PROTO_DIR}" ] || [ ! -d "${SDK_PROTO_DIR}" ]; then
    echo "ERROR: cannot resolve the SDK module dir even after 'go mod download'." >&2
    exit 1
  fi
  MISSION_PROTO="${SDK_PROTO_DIR}/api/proto/gibson/mission/v1/mission_definition.proto"
fi
if [ ! -f "${MISSION_PROTO}" ]; then
  echo "ERROR: mission proto not found at ${MISSION_PROTO}" >&2
  exit 1
fi
if [ ! -f "${DISPATCH_FILE}" ]; then
  echo "ERROR: dispatch file not found at ${DISPATCH_FILE} — if the switch" >&2
  echo "moved, update this guard rather than letting it rot (gibson#1399)." >&2
  exit 1
fi

NODE_TYPES=$(awk '
  /^enum NodeType[[:space:]]*{/ { in_enum = 1; next }
  in_enum && /^}/ { in_enum = 0; next }
  in_enum && /^[[:space:]]+NODE_TYPE_[A-Z_]+ *=/ {
    sub(/^[[:space:]]+/, "")
    sub(/ *=.*/, "")
    if ($0 != "NODE_TYPE_UNSPECIFIED") print $0
  }
' "${MISSION_PROTO}")

if [ -z "${NODE_TYPES}" ]; then
  echo "ERROR: parsed zero NodeType enum values from ${MISSION_PROTO}" >&2
  exit 1
fi

FAIL=0
COUNT=0
for NT in ${NODE_TYPES}; do
  COUNT=$((COUNT + 1))
  NOUN_LC=$(echo "${NT}" | sed 's/^NODE_TYPE_//' | tr '[:upper:]' '[:lower:]')
  CONFIG_NAME=""
  for w in ${NOUN_LC//_/ }; do
    CONFIG_NAME+="$(echo "${w:0:1}" | tr '[:lower:]' '[:upper:]')${w:1}"
  done
  CONFIG_NAME="${CONFIG_NAME}NodeConfig"

  # (a) config message variant in the proto
  if ! grep -q "${CONFIG_NAME} " "${MISSION_PROTO}"; then
    echo "FAIL ${NT}: missing oneof variant ${CONFIG_NAME} in ${MISSION_PROTO}" >&2
    FAIL=1
  fi

  # (b) dispatch arm in the real switch
  if ! grep -q "case .*NodeType_${NT}:" "${DISPATCH_FILE}"; then
    echo "FAIL ${NT}: no dispatch arm 'case …NodeType_${NT}:' in ${DISPATCH_FILE}" >&2
    FAIL=1
  fi

  # (c) e2e fixture
  E2E_FIXTURE="tests/e2e/missions/$(echo "${NOUN_LC}" | tr '_' '-').yaml"
  if [ ! -f "${E2E_FIXTURE}" ]; then
    echo "FAIL ${NT}: missing e2e fixture ${E2E_FIXTURE}" >&2
    FAIL=1
  fi

  # (d) a test in the dispatch package that references the NodeType
  if ! grep -rq "NodeType_${NT}\b" "${DISPATCH_TEST_DIR}"/*_test.go 2>/dev/null; then
    echo "FAIL ${NT}: no test in ${DISPATCH_TEST_DIR} references NodeType_${NT}" >&2
    FAIL=1
  fi
done

if [ "${FAIL}" -ne 0 ]; then
  echo "" >&2
  echo "check-noun-contract: at least one NodeType failed the contract." >&2
  echo "Adding a NodeType means: proto oneof variant + a case arm in" >&2
  echo "${DISPATCH_FILE} + an e2e fixture + a dispatch test." >&2
  echo "Spec: mission-verb-noun-registry Requirement 1. History: gibson#1399." >&2
  exit 1
fi

echo "check-noun-contract: ok — ${COUNT} NodeTypes carry all four pieces."
