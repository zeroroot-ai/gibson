#!/usr/bin/env bash
# check-tools.sh — call tools/list on an MCP endpoint and compare the tool
# names with expected-tools.txt (gibson#811).
#
# Usage: bash tests/fixtures/mcp-tools/check-tools.sh <mcp-url> [expected-file]
# Exit codes: 0 the names match, 1 they differ or the call failed, 2 usage.
set -euo pipefail

url=${1:?usage: $0 <mcp-url> [expected-file]}
expected=${2:-$(dirname "$0")/expected-tools.txt}
hdr=$(mktemp); trap 'rm -f "$hdr"' EXIT
accept='Accept: application/json, text/event-stream'

# The JSON of a response, from a JSON body or from the data line of an SSE body.
body_json() { sed -n 's/^data: //p; /^{/p' | head -1; }

curl -fsS -D "$hdr" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gibson-exit-test","version":"1"}}}' >/dev/null
session=$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *\([^[:space:]]*\).*/\1/p' "$hdr" | head -1)
sh=()
[ -n "$session" ] && sh=(-H "Mcp-Session-Id: $session")
curl -fsS "${sh[@]}" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
got=$(curl -fsS "${sh[@]}" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | body_json | jq -r '.result.tools[].name')
want=$(grep -v '^#' "$expected" | sed '/^$/d')
if [ "$got" != "$want" ]; then
  echo "::error::tools/list returned [$(echo "$got" | tr '\n' ' ')], want [$(echo "$want" | tr '\n' ' ')]"
  exit 1
fi
echo "tools/list returned the expected tools: $(echo "$got" | tr '\n' ' ')"
