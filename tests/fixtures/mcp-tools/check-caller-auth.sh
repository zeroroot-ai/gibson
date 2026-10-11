#!/usr/bin/env bash
# check-caller-auth.sh — prove that the proxy of a connector accepts only the
# daemon (ADR-0114). A call with no token and a call with a token for another
# audience are refused with 401. A call with the JWT-SVID of the daemon for
# the proxy audience is accepted.
#
# Usage: bash tests/fixtures/mcp-tools/check-caller-auth.sh <mcp-url> <daemon-token> <other-audience-token>
# Exit codes: 0 each answer is the one wanted, 1 one is not, 2 usage.
set -euo pipefail

url=${1:?usage: $0 <mcp-url> <daemon-token> <other-audience-token>}
good=${2:?usage: $0 <mcp-url> <daemon-token> <other-audience-token>}
other=${3:?usage: $0 <mcp-url> <daemon-token> <other-audience-token>}
accept='Accept: application/json, text/event-stream'
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"gibson-exit-test","version":"1"}}}'

# status prints the HTTP status of an initialize call, with the extra curl
# arguments of the caller. 000 is a call that got no answer.
status() {
  curl -sS -o /dev/null -w '%{http_code}' -m 20 "$@" -H 'Content-Type: application/json' -H "$accept" \
    -X POST "$url" -d "$init" || true
}

rc=0
got=$(status)
if [ "$got" = 401 ]; then
  echo "a call with no token: 401"
else
  echo "::error::the connector proxy answered a call with no token with $got, want 401"
  rc=1
fi
got=$(status -H "Authorization: Bearer ${other}")
if [ "$got" = 401 ]; then
  echo "a call with a token for another audience: 401"
else
  echo "::error::the connector proxy answered a token for another audience with $got, want 401"
  rc=1
fi
# The accepted call proves that the two refusals came from the token check,
# not from a proxy that refuses everything.
got=$(status -H "Authorization: Bearer ${good}")
case "$got" in
  2??) echo "a call with the token of the daemon: $got" ;;
  *)
    echo "::error::the connector proxy answered the token of the daemon with $got, want 2xx"
    rc=1
    ;;
esac
exit "$rc"
