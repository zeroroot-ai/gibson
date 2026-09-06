#!/usr/bin/env bash
# check-no-mcp-bridge.sh — build guard for ADR-0065 (mcp-bridge removed).
#
# MCP now lives ONLY in the connector domain, served via ToolHive behind the
# ConnectorInstance wrapper (ADR-0014). The legacy ADR-0048 mcp-bridge path —
# internal/engine/connector (ConnectorLauncher), the sdk/mcpbridge package, the
# `runtime: mcp-bridge` plugin runtime, and the manifest `mcp_bridge:` block —
# was removed by a hard cutover (ADR-0027, gibson#1524). The `plugin` domain has
# NO MCP: plugins are vendor-SDK, Go-first, JSON dispatch.
#
# This guard fails if any of that dead path reappears in gibson source. It scans
# Go and YAML for the tokens that uniquely identify the removed subsystem. The
# workspace ADRs under docs/ (0047/0048/0049 superseded, 0014/0065 explanatory)
# and CHANGELOG.md history intentionally name the removed path, so they are out
# of scope; this guard is a comment cannot be worked around by moving a mention
# there because the removal scrubbed every in-tree source mention.
#
# Exit codes:
#   0  No violations found.
#   1  One or more violations found.
#
# Self-test mode (SELFTEST=1):
#   Writes a synthetic violating fixture, asserts the scanner catches it, then
#   deletes the fixture. Exits 0 on a successful self-test, 1 if the scanner
#   fails to catch the violation. Ships proof the guard can fail (gibson rule:
#   every guard ships with a failing fixture).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELFTEST_FIXTURE="${REPO_ROOT}/internal/_check_mcp_bridge_selftest_fixture.yaml"

log_info()  { echo "[check-no-mcp-bridge] INFO:  $*"; }
log_error() { echo "[check-no-mcp-bridge] ERROR: $*" >&2; }

# The banned tokens. Each uniquely names the removed mcp-bridge subsystem and
# does NOT collide with the surviving ToolHive connector path (ConnectorInstance,
# ConnectorTransport, ConnectorService, connectorcatalog, connectorauth).
PATTERN='internal/engine/connector|sdk/mcpbridge|RuntimeMCPBridge|mcp-bridge|mcp_bridge|ConnectorLauncher'

cleanup_fixture() { rm -f "${SELFTEST_FIXTURE}"; }

# ---------------------------------------------------------------------------
# Self-test mode
# ---------------------------------------------------------------------------
if [[ "${SELFTEST:-0}" == "1" ]]; then
    log_info "Self-test mode: writing synthetic violating fixture..."
    trap cleanup_fixture EXIT
    mkdir -p "$(dirname "${SELFTEST_FIXTURE}")"
    cat > "${SELFTEST_FIXTURE}" <<'YAML'
# Synthetic fixture for self-test. Do not commit.
apiVersion: plugin.gibson.zeroroot.ai/v1
spec:
  runtime: mcp-bridge
  mcp_bridge:
    transport: stdio
YAML
    if SELFTEST=0 bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        log_error "SELFTEST FAILED: scanner did not detect the mcp-bridge fixture."
        exit 1
    fi
    log_info "SELFTEST PASSED: scanner correctly detected the violation."
    exit 0
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
log_info "Scanning Go and YAML source for removed mcp-bridge tokens..."

HITS="$(grep --recursive --line-number --extended-regexp --binary-files=without-match \
        --include='*.go' --include='*.yaml' --include='*.yml' \
        --exclude-dir='.git' --exclude-dir='.worktrees' --exclude-dir='.claude' \
        --exclude-dir='node_modules' --exclude-dir='docs' \
        "${PATTERN}" "${REPO_ROOT}" 2>/dev/null \
        | grep -v "check-no-mcp-bridge" \
        || true)"

if [[ -n "${HITS}" ]]; then
    log_error "Removed mcp-bridge path re-introduced (ADR-0065):"
    echo "${HITS}" | while IFS= read -r line; do echo "  ${line}"; done
    log_error ""
    log_error "MCP lives ONLY in the connector domain, served via ToolHive behind"
    log_error "the ConnectorInstance wrapper (ADR-0014). The plugin domain has NO"
    log_error "MCP: plugins are vendor-SDK, Go-first, JSON dispatch. Do NOT reintroduce"
    log_error "internal/engine/connector, sdk/mcpbridge, RuntimeMCPBridge, or an"
    log_error "mcp-bridge runtime. See ADR-0065."
    exit 1
fi

# Belt-and-braces: the removed package directory must not reappear.
if [[ -d "${REPO_ROOT}/internal/engine/connector" ]]; then
    log_error "internal/engine/connector/ has reappeared — it was removed by ADR-0065."
    exit 1
fi

log_info "No mcp-bridge references found. Guard passed."
exit 0
