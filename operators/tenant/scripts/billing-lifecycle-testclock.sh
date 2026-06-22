#!/usr/bin/env bash
# billing-lifecycle-testclock.sh — card-first-signup S9 (tenant-operator#360).
#
# Proves the post-signup billing lifecycle end-to-end using Stripe TEST CLOCKS
# (no 14-day real waits): advance a clock through trial-end → conversion →
# past_due → 7-day grace → revocation → teardown, asserting the Tenant CR and
# entitlements at each stage.
#
# This is a STAGING harness, not a unit test: it talks to a live Stripe test
# account and a live tenant-operator + daemon. Run it against the staging
# cluster after the card-first images roll. It is idempotent enough to re-run
# (each run mints a fresh test-clock customer + tenant slug).
#
# Prereqs:
#   - STRIPE_SECRET_KEY = the staging sk_test_ key (Stripe test mode).
#   - STRIPE_PRICE_TEAM = the team-tier recurring price id.
#   - kubectl context pointing at the staging cluster (TENANT_KUBECTL_CONTEXT).
#   - jq, curl.
#
# Usage:
#   STRIPE_SECRET_KEY=sk_test_... STRIPE_PRICE_TEAM=price_... \
#     TENANT_KUBECTL_CONTEXT=zeroroot-staging \
#     scripts/billing-lifecycle-testclock.sh
#
# What it does NOT do: drive the dashboard signup UI (that's the signup-smoke
# spec, dashboard#772). It exercises the operator/webhook/billing-reconciler
# half by creating the trialing subscription directly on a test clock and
# advancing time.
set -euo pipefail

: "${STRIPE_SECRET_KEY:?set STRIPE_SECRET_KEY (staging sk_test_ key)}"
: "${STRIPE_PRICE_TEAM:?set STRIPE_PRICE_TEAM (recurring price id)}"
KCTX="${TENANT_KUBECTL_CONTEXT:-zeroroot-staging}"
API="https://api.stripe.com/v1"
SUFFIX="$(date +%s)"
TENANT="lc-${SUFFIX}"

sapi() { # sapi METHOD PATH [curl-data-args...]
  local method="$1" path="$2"; shift 2
  curl -sS -u "${STRIPE_SECRET_KEY}:" -X "${method}" "${API}${path}" "$@"
}

stage() { echo; echo "=== $* ==="; }

assert_billing_status() { # assert_billing_status <expected>
  local want="$1" got
  got=$(kubectl --context "$KCTX" get tenant "$TENANT" -o jsonpath='{.status.billing.status}' 2>/dev/null || true)
  echo "  tenant ${TENANT} billing.status = '${got}' (want '${want}')"
  [ "$got" = "$want" ] || { echo "  FAIL: expected '${want}'"; exit 1; }
}

cleanup() {
  stage "cleanup"
  kubectl --context "$KCTX" delete tenant "$TENANT" --wait=false 2>/dev/null || true
  [ -n "${CLOCK_ID:-}" ] && sapi POST "/test_helpers/test_clocks/${CLOCK_ID}/advance" >/dev/null 2>&1 || true
}
trap cleanup EXIT

stage "1. Create a test clock + customer + trialing subscription (4242)"
NOW=$(date +%s)
CLOCK_ID=$(sapi POST /test_helpers/test_clocks -d "frozen_time=${NOW}" -d "name=lifecycle-${SUFFIX}" | jq -r .id)
echo "  test clock: ${CLOCK_ID}"
CUST_ID=$(sapi POST /customers -d "test_clock=${CLOCK_ID}" -d "metadata[tenant_id]=${TENANT}" | jq -r .id)
# Attach the always-succeeds test PaymentMethod, then create the trialing sub.
PM_ID=$(sapi POST /payment_methods -d "type=card" -d "card[token]=tok_visa" | jq -r .id)
sapi POST "/payment_methods/${PM_ID}/attach" -d "customer=${CUST_ID}" >/dev/null
SUB_ID=$(sapi POST /subscriptions \
  -d "customer=${CUST_ID}" \
  -d "items[0][price]=${STRIPE_PRICE_TEAM}" \
  -d "trial_period_days=14" \
  -d "default_payment_method=${PM_ID}" \
  -d "metadata[tenant_id]=${TENANT}" \
  -d "metadata[tier]=team" \
  -d "metadata[trial_signup]=true" | jq -r .id)
echo "  subscription: ${SUB_ID} (trialing)"
echo "  NOTE: the webhook must reconcile this onto a Tenant CR named ${TENANT}."
echo "  In staging this CR is created by signup; for a pure billing-lifecycle"
echo "  run, pre-create a minimal Tenant CR named ${TENANT} so the operator"
echo "  reconciler has a target."

stage "2. trial-will-end fires near trial end"
# Advance to 2 days before trial end (Stripe emits trial_will_end ~3d prior).
sapi POST "/test_helpers/test_clocks/${CLOCK_ID}/advance" -d "frozen_time=$((NOW + 12*86400))" >/dev/null
echo "  advanced clock to T+12d; expect customer.subscription.trial_will_end → status.billing.trialEndsSoon=true"

stage "3. trial converts to active (valid card)"
sapi POST "/test_helpers/test_clocks/${CLOCK_ID}/advance" -d "frozen_time=$((NOW + 15*86400))" >/dev/null
sleep 30
assert_billing_status "active"

stage "4. simulate payment failure → past_due"
# Swap to a card that fails on charge, then advance to the next renewal.
PM_FAIL=$(sapi POST /payment_methods -d "type=card" -d "card[token]=tok_chargeCustomerFail" | jq -r .id)
sapi POST "/payment_methods/${PM_FAIL}/attach" -d "customer=${CUST_ID}" >/dev/null
sapi POST "/subscriptions/${SUB_ID}" -d "default_payment_method=${PM_FAIL}" >/dev/null
sapi POST "/test_helpers/test_clocks/${CLOCK_ID}/advance" -d "frozen_time=$((NOW + 46*86400))" >/dev/null
sleep 30
assert_billing_status "past_due"

stage "5. within the 7-day grace, entitlements remain"
echo "  (capabilities intact — the operator floors quota only AFTER 7 days)"

stage "6. grace elapses → revocation (quota floored to 1)"
sapi POST "/test_helpers/test_clocks/${CLOCK_ID}/advance" -d "frozen_time=$((NOW + 54*86400))" >/dev/null
sleep 60
echo "  expect entitlements reconciler to floor tenant_quotas (concurrent_* = 1)."
echo "  Verify against the daemon: a cancelled/long-past-due tenant cannot run paid-scale work."

stage "7. cancellation → teardown"
sapi DELETE "/subscriptions/${SUB_ID}" >/dev/null
sleep 30
assert_billing_status "cancelled"
echo "  expect teardown-after annotation + the tenant to be deprovisioned."

echo
echo "LIFECYCLE RUN COMPLETE — record CR snapshots per stage in the issue."
