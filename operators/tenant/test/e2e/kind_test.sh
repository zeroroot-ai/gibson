#!/usr/bin/env bash
# E2E smoke test for gibson-tenant-operator against a Kind cluster.
# Idempotent: cleans up on exit, safe to rerun.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-gibson-tenant-op-e2e}"
IMAGE="${IMAGE:-gibson-tenant-operator:e2e}"
NAMESPACE="${NAMESPACE:-gibson-platform}"

cleanup() {
  echo ">> cleanup"
  kubectl --context "kind-${CLUSTER_NAME}" delete tenant acme-e2e --ignore-not-found --timeout=30s || true
  if [[ "${KEEP_CLUSTER:-false}" != "true" ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" || true
  fi
}
trap cleanup EXIT

echo ">> creating kind cluster ${CLUSTER_NAME}"
if ! kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
  kind create cluster --name "${CLUSTER_NAME}"
fi

echo ">> building operator image"
cd "${REPO_ROOT}"
docker build -t "${IMAGE}" .

echo ">> loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

echo ">> creating platform namespace"
kubectl --context "kind-${CLUSTER_NAME}" create namespace "${NAMESPACE}" --dry-run=client -o yaml | \
  kubectl --context "kind-${CLUSTER_NAME}" apply -f -

echo ">> installing CRDs"
kubectl --context "kind-${CLUSTER_NAME}" apply -f "${REPO_ROOT}/config/crd/bases/"

echo ">> deploying operator"
kustomize build "${REPO_ROOT}/config/default" | \
  sed "s|controller:latest|${IMAGE}|g" | \
  kubectl --context "kind-${CLUSTER_NAME}" apply -f -

echo ">> waiting for operator Ready (120s)"
kubectl --context "kind-${CLUSTER_NAME}" -n "${NAMESPACE}" wait --for=condition=Available deployment/gibson-tenant-operator --timeout=120s || \
  kubectl --context "kind-${CLUSTER_NAME}" -n "${NAMESPACE}" wait --for=condition=Available deployment/tenant-operator-controller-manager --timeout=120s

echo ">> applying test Tenant"
kubectl --context "kind-${CLUSTER_NAME}" apply -f - <<EOF
apiVersion: gibson.zeroroot.ai/v1alpha1
kind: Tenant
metadata:
  name: acme-e2e
spec:
  displayName: "Acme E2E"
  owner: "e2e@example.com"
  tier: free
EOF

echo ">> waiting for Tenant to reach Ready (60s)"
for i in $(seq 1 30); do
  phase=$(kubectl --context "kind-${CLUSTER_NAME}" get tenant acme-e2e -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  echo "  phase=${phase}"
  if [[ "${phase}" == "Ready" ]]; then
    break
  fi
  sleep 2
done
[[ "${phase}" == "Ready" ]] || { echo "Tenant did not reach Ready phase"; exit 1; }

echo ">> verifying tenant namespace + NetworkPolicy + ResourceQuota"
kubectl --context "kind-${CLUSTER_NAME}" get namespace tenant-acme-e2e
kubectl --context "kind-${CLUSTER_NAME}" -n tenant-acme-e2e get networkpolicy gibson-tenant-default-deny
kubectl --context "kind-${CLUSTER_NAME}" -n tenant-acme-e2e get resourcequota gibson-tenant-quota

echo ">> deleting Tenant"
kubectl --context "kind-${CLUSTER_NAME}" delete tenant acme-e2e --timeout=120s

echo ">> verifying namespace was cleaned up"
for i in $(seq 1 30); do
  if ! kubectl --context "kind-${CLUSTER_NAME}" get namespace tenant-acme-e2e >/dev/null 2>&1; then
    echo "  namespace deleted"
    break
  fi
  sleep 2
done

echo ">> E2E SUCCESS"
