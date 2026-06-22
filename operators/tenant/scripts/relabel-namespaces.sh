#!/usr/bin/env bash
# Migrates gibson.zero-day.ai/* label keys to gibson.zeroroot.ai/* on all K8s objects.
# Run against kind cluster after tenant-operator is updated.
set -euo pipefail

OLD_DOMAIN="gibson.zero-day.ai"
NEW_DOMAIN="gibson.zeroroot.ai"

echo "Relabeling Namespaces..."
kubectl get namespaces -o json | jq -r '.items[] | select(.metadata.labels | keys[] | startswith("'"$OLD_DOMAIN"'")) | .metadata.name' | while read ns; do
  labels=$(kubectl get namespace "$ns" -o json | jq -r '.metadata.labels | to_entries[] | select(.key | startswith("'"$OLD_DOMAIN"'")) | "'"$NEW_DOMAIN"'/" + (.key | ltrimstr("'"$OLD_DOMAIN"'/")) + "=" + .value' | tr '\n' ' ')
  echo "Relabeling namespace $ns: $labels"
  kubectl label namespace "$ns" $labels --overwrite
done

echo "Done. Verify with: kubectl get ns --show-labels | grep zeroroot"
