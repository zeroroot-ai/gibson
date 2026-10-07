#!/usr/bin/env bash
# probe-egress.sh — call the probe_egress tool of the fixture connector and
# check its answer (gibson#758).
#
# Usage: bash tests/fixtures/mcp-tools/probe-egress.sh <mcp-url> <host:port> <reachable|unreachable>
# Exit codes: 0 the answer is the one wanted, 1 it is not or the call failed, 2 usage.
set -euo pipefail

url=${1:?usage: $0 <mcp-url> <host:port> <reachable|unreachable>}
address=${2:?usage: $0 <mcp-url> <host:port> <reachable|unreachable>}
want=${3:?usage: $0 <mcp-url> <host:port> <reachable|unreachable>}
case "$want" in reachable|unreachable) ;; *) echo "usage: want is reachable or unreachable" >&2; exit 2 ;; esac
hdr=$(mktemp); trap 'rm -f "$hdr"' EXIT
accept='Accept: application/json, text/event-stream'
body_json() { sed -n 's/^data: //p; /^{/p' | head -1; }

curl -fsS -D "$hdr" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gibson-exit-test","version":"1"}}}' >/dev/null
session=$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: *\([^[:space:]]*\).*/\1/p' "$hdr" | head -1)
sh=()
[ -n "$session" ] && sh=(-H "Mcp-Session-Id: $session")
curl -fsS "${sh[@]}" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
got=$(curl -fsS -m 30 "${sh[@]}" -H 'Content-Type: application/json' -H "$accept" -X POST "$url" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"probe_egress\",\"arguments\":{\"address\":\"$address\"}}}" \
  | body_json | jq -r '.result.content[0].text // .error.message')
case "$got" in
  "$want"|"$want: "*) echo "probe_egress $address: $got"; exit 0 ;;
esac
echo "::error::probe_egress $address answered '$got', want $want"
exit 1
