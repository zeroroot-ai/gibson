#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# Deploy the mock model provider into the kind cluster of an exit test. All
# exit tests that use the mock call this script, so there is one way to deploy
# it. The script runs from the root of the gibson checkout.
#
#   1. Build the image and load it into kind.
#   2. Make a CA and a certificate for the Service name of the mock.
#   3. Apply mockprovider.yaml and wait for the rollout.
#   4. Write the two URLs of the mock to the env file that run-e2e-job.sh reads.
#
# Inputs (environment):
#   CLUSTER   the kind cluster name
#   E2E_OUT   the directory for the run files. The script copies the CA to it.
# Argument 1: the path of the env file to write.
set -euo pipefail

: "${CLUSTER:?CLUSTER is not set}"
: "${E2E_OUT:?E2E_OUT is not set}"
env_file=${1:?usage: deploy.sh <env-file>}

MOCK_NS=gibson-e2e-mock
MOCK_HOST=mock-provider.${MOCK_NS}.svc.cluster.local
IMG=ghcr.io/zeroroot-ai/gibson-fixture-mockprovider:e2e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

docker build -f "$here/Dockerfile" -t "$IMG" "$root"
kind load docker-image "$IMG" --name "$CLUSTER"
kubectl apply -f "$here/mockprovider.yaml"

dir=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=mock-provider-ca" \
  -keyout "$dir/ca.key" -out "$dir/ca.crt"
openssl req -newkey rsa:2048 -nodes -subj "/CN=${MOCK_HOST}" \
  -keyout "$dir/tls.key" -out "$dir/tls.csr"
printf 'subjectAltName=DNS:%s\n' "$MOCK_HOST" > "$dir/san.ext"
openssl x509 -req -in "$dir/tls.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
  -days 1 -extfile "$dir/san.ext" -out "$dir/tls.crt"
kubectl -n "$MOCK_NS" create secret generic mock-provider-tls \
  --from-file=tls.crt="$dir/tls.crt" --from-file=tls.key="$dir/tls.key" --from-file=ca.crt="$dir/ca.crt"
mkdir -p "$E2E_OUT"
cp "$dir/ca.crt" "$E2E_OUT/mock-ca.crt"
kubectl -n "$MOCK_NS" rollout status deployment/mock-provider --timeout=5m
{
  echo "GIBSON_E2E_MOCK_PROVIDER_URL=https://${MOCK_HOST}"
  echo "GIBSON_E2E_MOCK_RECORDED_URL=http://${MOCK_HOST}"
} > "$env_file"
