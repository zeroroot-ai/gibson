#!/usr/bin/env bash
# check-operator-rbac-scope.sh — the tenant-operator's ClusterRole stays
# cluster-scope-only.
#
# Spec: secrets-blast-radius-reduction. The invariant is stated in
# operators/tenant/internal/controller/tenant_controller.go, above the
# kubebuilder:rbac markers: per-namespace resources are NOT granted
# cluster-wide. They come from two narrower places instead —
#
#   - the chart's release-namespace Role + RoleBinding
#     (templates/tenant-operator/release-namespace-rbac.yaml in zeroroot-ai/charts),
#     for the operator's own bootstrap traffic; and
#   - a per-tenant Role + RoleBinding that
#     NamespaceProvisioner.ensureTenantNamespaceRBAC writes inside the tenant's
#     namespace at runtime, owned by that Namespace so it is collected on delete.
#
# A cluster-wide grant for any of them would hand the operator read access to
# every Secret in the cluster, which is the blast radius the spec exists to
# shrink. Kubebuilder markers cannot express dynamic per-tenant scope, so nothing
# in the generator stops a marker being widened — which is what this checks.
#
# That comment has claimed this script exists since the spec landed, and until
# now it did not: the invariant held by review alone (gibson#557).
#
# Two surfaces, because either one can drift on its own:
#   1. the +kubebuilder:rbac markers in the operator's controllers, which are
#      the source; and
#   2. config/rbac/role.yaml, the generated ClusterRole, which is what is
#      applied. A hand-edit there would not show up in the markers.
#
# Self-test (--selftest) drives both scanners over synthetic trees, asserting a
# clean tree passes and that one violation of each surface fails with the
# resource named. Touches nothing real.
#
# Exit codes:
#   0  No cluster-wide grant for a namespaced resource.
#   1  At least one, or the scan was too small to trust.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log_info() { echo "[check-operator-rbac-scope] INFO:  $*"; }
log_error() { echo "[check-operator-rbac-scope] ERROR: $*" >&2; }

# The namespaced resources named in the invariant. A cluster-wide grant for any
# of them is the defect.
FORBIDDEN=(
  secrets
  configmaps
  services
  persistentvolumeclaims
  resourcequotas
  statefulsets
  networkpolicies
  roles
  rolebindings
  leases
)

# scan_markers reports a forbidden resource in any +kubebuilder:rbac marker under
# $1. Markers list resources semicolon-separated: resources=secrets;configmaps.
scan_markers() {
  local dir="$1" found=0 file line res
  while IFS= read -r hit; do
    file="${hit%%:*}"
    line="${hit#*:}"
    line="${line%%:*}"
    local text="${hit#*:*:}"
    # Pull the resources= list out, split it, and test each entry exactly.
    local list
    list="$(printf '%s' "$text" | sed -n 's/.*resources=\([a-zA-Z0-9;/_-]*\).*/\1/p')"
    [ -z "$list" ] && continue
    local IFS_SAVE="$IFS"
    IFS=';'
    for res in $list; do
      IFS="$IFS_SAVE"
      for bad in "${FORBIDDEN[@]}"; do
        if [ "$res" = "$bad" ]; then
          log_error "$file:$line grants cluster-wide '$bad' in a +kubebuilder:rbac marker."
          log_error "  '$bad' is namespaced. Grant it in the chart's release-namespace Role,"
          log_error "  or at runtime through NamespaceProvisioner.ensureTenantNamespaceRBAC."
          found=1
        fi
      done
      IFS=';'
    done
    IFS="$IFS_SAVE"
  done < <(grep -rn '+kubebuilder:rbac' "$dir" 2>/dev/null || true)
  return "$found"
}

# scan_role reports a forbidden resource in a generated ClusterRole at $1. The
# file is a YAML list of rules; a resource sits on its own `- name` line under
# `resources:`, so the check is per line within a resources block.
scan_role() {
  local role="$1" found=0 in_resources=0 lineno=0 line res
  [ -f "$role" ] || {
    log_error "$role does not exist; the generated ClusterRole is what gets applied."
    return 1
  }
  while IFS= read -r line; do
    lineno=$((lineno + 1))
    case "$line" in
    *"resources:"*)
      in_resources=1
      continue
      ;;
    *"verbs:"* | *"apiGroups:"* | *"- apiGroups"*)
      in_resources=0
      continue
      ;;
    esac
    [ "$in_resources" -eq 1 ] || continue
    res="$(printf '%s' "$line" | sed -n 's/^[[:space:]]*-[[:space:]]*\([a-zA-Z0-9/_-]*\)[[:space:]]*$/\1/p')"
    [ -z "$res" ] && continue
    for bad in "${FORBIDDEN[@]}"; do
      if [ "$res" = "$bad" ]; then
        log_error "$role:$lineno grants cluster-wide '$bad' in the generated ClusterRole."
        log_error "  Re-run the generator after narrowing the marker; do not hand-edit this file."
        found=1
      fi
    done
  done <"$role"
  return "$found"
}

# ---------------------------------------------------------------------------
# Self-test — one fixture per surface, asserting the resource is named.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--selftest" ]; then
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  mkdir -p "$TMP/clean"
  cat >"$TMP/clean/ok.go" <<'EOF'
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants,verbs=get;list
// +kubebuilder:rbac:groups=core,resources=namespaces;events,verbs=create
EOF
  log_info "Self-test: markers with no namespaced resource must pass..."
  if ! scan_markers "$TMP/clean"; then
    log_error "Self-test FAILED: a clean marker set was reported as a violation."
    exit 1
  fi

  mkdir -p "$TMP/dirty"
  cat >"$TMP/dirty/bad.go" <<'EOF'
// +kubebuilder:rbac:groups=core,resources=namespaces;secrets,verbs=get;list
EOF
  log_info "Self-test: a marker granting cluster-wide secrets must fail, naming it..."
  if out="$(scan_markers "$TMP/dirty" 2>&1)"; then
    log_error "Self-test FAILED: a cluster-wide 'secrets' marker passed."
    exit 1
  fi
  case "$out" in
  *"cluster-wide 'secrets'"*) ;;
  *)
    log_error "Self-test FAILED: the refusal did not name 'secrets'. Got: $out"
    exit 1
    ;;
  esac

  cat >"$TMP/clean-role.yaml" <<'EOF'
rules:
- apiGroups:
  - ""
  resources:
  - namespaces
  verbs:
  - get
EOF
  log_info "Self-test: a ClusterRole with no namespaced resource must pass..."
  if ! scan_role "$TMP/clean-role.yaml"; then
    log_error "Self-test FAILED: a clean ClusterRole was reported as a violation."
    exit 1
  fi

  cat >"$TMP/dirty-role.yaml" <<'EOF'
rules:
- apiGroups:
  - ""
  resources:
  - namespaces
  - configmaps
  verbs:
  - get
EOF
  log_info "Self-test: a ClusterRole granting configmaps must fail, naming it..."
  if out="$(scan_role "$TMP/dirty-role.yaml" 2>&1)"; then
    log_error "Self-test FAILED: a cluster-wide 'configmaps' rule passed."
    exit 1
  fi
  case "$out" in
  *"cluster-wide 'configmaps'"*) ;;
  *)
    log_error "Self-test FAILED: the refusal did not name 'configmaps'. Got: $out"
    exit 1
    ;;
  esac

  log_info "Self-test: 4 passed."
  exit 0
fi

# ---------------------------------------------------------------------------
# The real scan.
# ---------------------------------------------------------------------------
CONTROLLERS="$REPO_ROOT/operators/tenant/internal/controller"
ROLE="$REPO_ROOT/operators/tenant/config/rbac/role.yaml"

# A floor, so a wrong cwd or a moved directory cannot report success having read
# nothing. The operator has a dozen controllers; 5 is far under and far over
# whatever a broken checkout produces.
marker_count="$(grep -rc '+kubebuilder:rbac' "$CONTROLLERS" 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')"
if [ "${marker_count:-0}" -lt 5 ]; then
  log_error "found only ${marker_count:-0} +kubebuilder:rbac marker(s) under $CONTROLLERS."
  log_error "The operator has many. Refusing to pass on a scan that read almost nothing."
  exit 1
fi

log_info "checking $marker_count marker(s) and the generated ClusterRole..."

status=0
scan_markers "$CONTROLLERS" || status=1
scan_role "$ROLE" || status=1

if [ "$status" -ne 0 ]; then
  log_error "The tenant-operator ClusterRole must stay cluster-scope-only."
  log_error "See the invariant above the markers in internal/controller/tenant_controller.go."
  exit 1
fi

log_info "OK — no cluster-wide grant for a namespaced resource."
