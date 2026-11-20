#!/usr/bin/env bash
# Build the reference environment on kind with one command (gibson#1490).
# It needs kind, kubectl and a container runtime. It uses its own kubeconfig,
# so it never changes the current context of the caller.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
name=${REFENV_CLUSTER:-refenv}
export KUBECONFIG=${REFENV_KUBECONFIG:-${TMPDIR:-/tmp}/${name}.kubeconfig}

kind create cluster --name "$name" --config "$here/kind-config.yaml" --wait 120s
kubectl apply -k "$here"

for deploy in gitea act-runner prometheus blackbox-exporter \
  catalog-api payments node-agent log-shipper ops-dashboard reports; do
  kubectl -n refenv rollout status "deployment/$deploy" --timeout=300s
done
kubectl -n refenv wait --for=condition=complete job/seed --timeout=300s

echo "The reference environment is up."
echo "KUBECONFIG=$KUBECONFIG"
