#!/usr/bin/env bash
# check-noun-contract — enforces the four-step verb/noun
# extension contract from mission-verb-noun-registry Requirement 1.
#
# For every NodeType enum value in the SDK proto, verify:
#   (a) a *NodeConfig variant in MissionNode.config oneof,
#   (b) a registered handler resolvable at runtime,
#   (c) at least one e2e fixture under tests/e2e/missions/,
#   (d) at least one unit test in internal/orchestrator/nodes/<noun>/.
#
# Exits non-zero on any missing piece.
#
# Spec: mission-verb-noun-registry Requirement 1.

set -euo pipefail

SDK_PROTO_DIR="$(go list -m -f '{{.Dir}}' github.com/zeroroot-ai/sdk 2>/dev/null || true)"
if [ -z "${SDK_PROTO_DIR}" ]; then
  echo "ERROR: cannot resolve SDK proto dir via 'go list -m'." >&2
  exit 1
fi
MISSION_PROTO="${SDK_PROTO_DIR}/api/proto/gibson/mission/v1/mission_definition.proto"
if [ ! -f "${MISSION_PROTO}" ]; then
  echo "ERROR: mission proto not found at ${MISSION_PROTO}" >&2
  exit 1
fi

# Parse NodeType enum values (excluding UNSPECIFIED).
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
for NT in ${NODE_TYPES}; do
  # Convert NODE_TYPE_FOO_BAR → FooBarNodeConfig.
  NOUN_LC=$(echo "${NT}" | sed 's/^NODE_TYPE_//' | tr '[:upper:]' '[:lower:]')
  CONFIG_NAME=""
  for w in ${NOUN_LC//_/ }; do
    CONFIG_NAME+="$(echo "${w:0:1}" | tr '[:lower:]' '[:upper:]')${w:1}"
  done
  CONFIG_NAME="${CONFIG_NAME}NodeConfig"

  # (a) config message in oneof
  if ! grep -q "${CONFIG_NAME} " "${MISSION_PROTO}"; then
    echo "FAIL ${NT}: missing oneof variant ${CONFIG_NAME} in ${MISSION_PROTO}" >&2
    FAIL=1
  fi

  # (b) runtime handler — every per-noun package under
  # internal/orchestrator/nodes/<noun>/ must call
  # RegisterNodeHandler(NodeType_<NT>, ...).
  NODE_DIR="internal/orchestrator/nodes/${NOUN_LC}"
  if [ -d "${NODE_DIR}" ]; then
    if ! grep -rq "RegisterNodeHandler.*NodeType_${NT}" "${NODE_DIR}"; then
      echo "FAIL ${NT}: ${NODE_DIR} exists but does not call RegisterNodeHandler(NodeType_${NT}, ...)" >&2
      FAIL=1
    fi
  else
    echo "FAIL ${NT}: missing handler package ${NODE_DIR}" >&2
    FAIL=1
  fi

  # (c) e2e fixture
  E2E_FIXTURE="tests/e2e/missions/$(echo "${NOUN_LC}" | tr '_' '-').yaml"
  if [ ! -f "${E2E_FIXTURE}" ]; then
    echo "FAIL ${NT}: missing e2e fixture ${E2E_FIXTURE}" >&2
    FAIL=1
  fi

  # (d) unit tests
  if [ -d "${NODE_DIR}" ]; then
    if ! find "${NODE_DIR}" -name '*_test.go' -print -quit | grep -q .; then
      echo "FAIL ${NT}: no unit tests under ${NODE_DIR}" >&2
      FAIL=1
    fi
  fi
done

if [ "${FAIL}" -ne 0 ]; then
  echo "" >&2
  echo "check-noun-contract: at least one NodeType failed the contract." >&2
  echo "Spec: mission-verb-noun-registry Requirement 1." >&2
  exit 1
fi

echo "check-noun-contract: ok — every NodeType has its four pieces."
