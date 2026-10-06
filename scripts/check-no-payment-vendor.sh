#!/usr/bin/env bash
# check-no-payment-vendor.sh — CI guard: gibson Go code does not reach a
# payment vendor.
#
# Why: billing is one private component (ADR-0060, D54, gibson#713). The public
# code has three neutral connection points and does not know that a payment
# vendor exists. The tenant operator once called the Stripe API directly. This
# guard fails on a Stripe API host, a Stripe Go import, or a STRIPE_ variable
# in non-test Go code. Keyed by content, never by path or line number.
#
# Usage:
#   bash scripts/check-no-payment-vendor.sh            # real check
#   bash scripts/check-no-payment-vendor.sh --selftest # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail

# The three forms of a vendor dependency: the API host, the Go module, and an
# environment variable of the vendor.
PATTERN='stripe\.com|"github\.com/stripe/|STRIPE_'

list_files() {
  if [ -n "${SCAN_ROOT:-}" ]; then
    find "$SCAN_ROOT" -type f -name '*.go' ! -name '*_test.go' -print0
  else
    git ls-files -z -- '*.go' ':!:*_test.go' ':!:**/testdata/**'
  fi
}

scan() {
  local hits
  hits=$(list_files | xargs -0 -r grep -n -E -- "$PATTERN" || true)
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      echo "::error file=${line%%:*}::payment vendor reference: ${line#*:}"
    done <<<"$hits"
    echo "check-no-payment-vendor: gibson Go code references a payment vendor. Billing is a private component (ADR-0060)." >&2
    return 1
  fi
  echo "check-no-payment-vendor: no payment vendor reference."
}

selftest() {
  local rc
  tmp=$(mktemp -d); trap "rm -rf '$tmp'" EXIT
  # case 1: each of the three forms must be rejected.
  for i in 1 2 3; do mkdir -p "$tmp/bad$i"; done
  printf 'package a\nconst u = "https://api.stripe.com/v1"\n' > "$tmp/bad1/a.go"
  printf 'package a\nimport _ "github.com/stripe/stripe-go/v82"\n' > "$tmp/bad2/a.go"
  printf 'package a\nimport "os"\nvar k = os.Getenv("STRIPE_API_KEY")\n' > "$tmp/bad3/a.go"
  for i in 1 2 3; do
    rc=0; SCAN_ROOT="$tmp/bad$i" scan >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 1 ]; then echo "SELFTEST case 1.$i FAILED: vendor reference not rejected (rc=$rc)" >&2; return 1; fi
  done
  echo "SELFTEST case 1 PASSED: host, import and variable fixtures rejected."
  # case 2: neutral code, and a test file that names the vendor, must pass.
  mkdir -p "$tmp/good"
  printf 'package a\n// The billing component owns the payment vendor.\nconst seam = "GIBSON_SIGNUP_STEP_URL"\n' > "$tmp/good/a.go"
  printf 'package a\nconst fixture = "STRIPE_API_KEY"\n' > "$tmp/good/a_test.go"
  SCAN_ROOT="$tmp/good" scan >/dev/null 2>&1 || { echo "SELFTEST case 2 FAILED: clean tree rejected" >&2; return 1; }
  echo "SELFTEST case 2 PASSED: clean tree accepted."
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
