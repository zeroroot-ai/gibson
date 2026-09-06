#!/usr/bin/env bash
# orphan-cleanup-e2e.sh
#
# End-to-end smoke for tenant-orphan-user-cleanup spec.
#
# Scenarios:
#   A) Orphan path  — single tenant whose owner is in no other org. Deletion
#      should remove both the tenant and the owner's user row.
#   B) Multi-org path — two tenants share an owner email. Deleting one tenant
#      must leave the user row intact (still a member of the other org).
#
# Targets the `gibson` Kind cluster. Requires the updated operator and
# dashboard images already loaded into the cluster.
#
# Exits non-zero on any failed assertion.

set -euo pipefail

CONTEXT="${CONTEXT:-kind-gibson}"
NS="${NS:-gibson}"
PG_POD="${PG_POD:-gibson-dashboard-postgresql-0}"
ORPHAN_OWNER="e2e-orphan-$(date +%s)@test.local"
SHARED_OWNER="e2e-shared-$(date +%s)@test.local"
TENANT_A="e2e-orphan-${RANDOM}"
TENANT_B="e2e-multi-a-${RANDOM}"
TENANT_C="e2e-multi-b-${RANDOM}"
TIMEOUT_PROVISION=180
TIMEOUT_DELETE=180

die() { echo "FAIL: $*" >&2; exit 1; }
log() { echo "[orphan-e2e] $*"; }

# ----- helpers ---------------------------------------------------------------

pg_query() {
    local pw
    pw="$(kubectl --context "$CONTEXT" -n "$NS" exec "$PG_POD" -- bash -c 'echo $POSTGRES_PASSWORD')"
    kubectl --context "$CONTEXT" -n "$NS" exec "$PG_POD" -- env PGPASSWORD="$pw" \
        psql -U dashboard -d dashboard -tAc "$1"
}

user_exists() {
    local email="$1"
    local count
    count="$(pg_query "SELECT count(*) FROM \"user\" WHERE email = '$email';")"
    [[ "$count" == "1" ]]
}

apply_tenant() {
    local name="$1" owner="$2"
    cat <<EOF | kubectl --context "$CONTEXT" apply -f -
apiVersion: gibson.zeroroot.ai/v1alpha1
kind: Tenant
metadata:
  name: $name
spec:
  displayName: ${name}-display
  owner: $owner
  tier: free
EOF
}

wait_tenant_ready() {
    local name="$1"
    log "waiting for tenant/$name Phase=Ready (timeout ${TIMEOUT_PROVISION}s)..."
    local end=$(( SECONDS + TIMEOUT_PROVISION ))
    while [[ $SECONDS -lt $end ]]; do
        local phase
        phase="$(kubectl --context "$CONTEXT" get tenant "$name" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")"
        if [[ "$phase" == "Ready" ]]; then return 0; fi
        sleep 3
    done
    kubectl --context "$CONTEXT" get tenant "$name" -o yaml | tail -40 >&2
    die "tenant/$name did not reach Ready within ${TIMEOUT_PROVISION}s"
}

wait_tenant_gone() {
    local name="$1"
    log "waiting for tenant/$name to disappear (timeout ${TIMEOUT_DELETE}s)..."
    local end=$(( SECONDS + TIMEOUT_DELETE ))
    while [[ $SECONDS -lt $end ]]; do
        if ! kubectl --context "$CONTEXT" get tenant "$name" >/dev/null 2>&1; then
            return 0
        fi
        sleep 3
    done
    kubectl --context "$CONTEXT" get tenant "$name" -o yaml | tail -40 >&2
    die "tenant/$name still present after ${TIMEOUT_DELETE}s"
}

cleanup() {
    log "cleanup: removing any stragglers..."
    kubectl --context "$CONTEXT" delete tenant "$TENANT_A" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl --context "$CONTEXT" delete tenant "$TENANT_B" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    kubectl --context "$CONTEXT" delete tenant "$TENANT_C" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ----- preflight -------------------------------------------------------------

kubectl --context "$CONTEXT" -n "$NS" get pod "$PG_POD" >/dev/null \
    || die "dashboard postgres pod $PG_POD not found in namespace $NS on context $CONTEXT"

log "preflight ok. context=$CONTEXT ns=$NS"

# ----- Scenario A: orphan ----------------------------------------------------

log "=== Scenario A: orphan owner ==="
log "creating tenant $TENANT_A with owner=$ORPHAN_OWNER"
apply_tenant "$TENANT_A" "$ORPHAN_OWNER"
wait_tenant_ready "$TENANT_A"

if ! user_exists "$ORPHAN_OWNER"; then
    pg_query "SELECT id, email FROM \"user\";" >&2
    die "expected user $ORPHAN_OWNER to exist after tenant provision"
fi
log "user $ORPHAN_OWNER provisioned ✓"

log "deleting tenant $TENANT_A"
kubectl --context "$CONTEXT" delete tenant "$TENANT_A" --wait=false
wait_tenant_gone "$TENANT_A"

# Give the operator one last reconcile pass to flush the sweep.
sleep 2

if user_exists "$ORPHAN_OWNER"; then
    pg_query "SELECT id, email FROM \"user\" WHERE email = '$ORPHAN_OWNER';" >&2
    die "Scenario A FAILED: user $ORPHAN_OWNER still exists after tenant deletion (orphan cleanup did not delete)"
fi
log "Scenario A PASSED: user $ORPHAN_OWNER cleaned up ✓"

# ----- Scenario B: multi-org -------------------------------------------------

log "=== Scenario B: multi-org owner is preserved ==="
log "creating tenant $TENANT_B with owner=$SHARED_OWNER"
apply_tenant "$TENANT_B" "$SHARED_OWNER"
wait_tenant_ready "$TENANT_B"

log "creating tenant $TENANT_C with same owner=$SHARED_OWNER"
apply_tenant "$TENANT_C" "$SHARED_OWNER"
wait_tenant_ready "$TENANT_C"

if ! user_exists "$SHARED_OWNER"; then
    die "expected user $SHARED_OWNER to exist after second tenant provision"
fi
membership_count="$(pg_query "SELECT count(*) FROM member m JOIN \"user\" u ON m.\"userId\" = u.id WHERE u.email = '$SHARED_OWNER';")"
if [[ "$membership_count" != "2" ]]; then
    pg_query "SELECT m.\"organizationId\", m.role, u.email FROM member m JOIN \"user\" u ON m.\"userId\" = u.id WHERE u.email = '$SHARED_OWNER';" >&2
    die "expected $SHARED_OWNER to have 2 memberships, got $membership_count"
fi
log "user $SHARED_OWNER is in 2 orgs ✓"

log "deleting only tenant $TENANT_B (leaves $TENANT_C)"
kubectl --context "$CONTEXT" delete tenant "$TENANT_B" --wait=false
wait_tenant_gone "$TENANT_B"
sleep 2

if ! user_exists "$SHARED_OWNER"; then
    die "Scenario B FAILED: user $SHARED_OWNER was deleted even though they still belong to $TENANT_C"
fi
membership_count_after="$(pg_query "SELECT count(*) FROM member m JOIN \"user\" u ON m.\"userId\" = u.id WHERE u.email = '$SHARED_OWNER';")"
if [[ "$membership_count_after" != "1" ]]; then
    die "expected $SHARED_OWNER to have 1 membership remaining (in $TENANT_C), got $membership_count_after"
fi
log "Scenario B PASSED: user $SHARED_OWNER preserved with 1 remaining membership ✓"

log "deleting final tenant $TENANT_C — user should now be orphaned and cleaned"
kubectl --context "$CONTEXT" delete tenant "$TENANT_C" --wait=false
wait_tenant_gone "$TENANT_C"
sleep 2

if user_exists "$SHARED_OWNER"; then
    die "Scenario B FAILED (post-final-delete): user $SHARED_OWNER still exists after all their tenants were deleted"
fi
log "Scenario B post-cleanup ✓: $SHARED_OWNER cleaned up after final tenant gone"

log "ALL SCENARIOS PASSED"
