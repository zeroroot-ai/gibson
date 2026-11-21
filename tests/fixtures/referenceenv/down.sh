#!/usr/bin/env bash
# Delete the kind cluster of the reference environment.
set -euo pipefail
name=${REFENV_CLUSTER:-refenv}
kind delete cluster --name "$name"
