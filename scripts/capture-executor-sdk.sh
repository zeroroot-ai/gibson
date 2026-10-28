#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0
# Copyright 2026 Zero Root AI
#
# capture-executor-sdk.sh <image> — record the sdk version that a digest-pinned
# gibson-executor image was built on, in internal/platform/componentcatalog/
# executor-sdk.json (gibson#1343).
#
# Every first-party tool answers with a DiscoveryResult built from the sdk of
# the image. The daemon reads it with the sdk of the daemon, and a field that the
# sdk removed between the two makes the whole result unreadable. The wire guard
# in the componentcatalog package reads this file to catch that skew.
#
# The version comes from the module list in the binary (go version -m), so it
# is what the image holds and not what its repository says.
set -euo pipefail

IMAGE="${1:?usage: capture-executor-sdk.sh <image@sha256:...>}"
OUT="${CAP_SDK_OUT:-internal/platform/componentcatalog/executor-sdk.json}"
case "$IMAGE" in *@sha256:*) ;; *) echo "capture-executor-sdk: $IMAGE is not digest-pinned" >&2; exit 1 ;; esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cid="$(docker create "$IMAGE")"
trap 'docker rm "$cid" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
docker cp "$cid:/usr/local/bin/gibson-runner" "$tmp/gibson-runner"
version="$(go version -m "$tmp/gibson-runner" | awk '$1=="dep" && $2=="github.com/zeroroot-ai/sdk" {print $3}')"
if ! printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "capture-executor-sdk: the binary of $IMAGE names no sdk release version (got '$version')" >&2
  exit 1
fi
printf '{\n  "image": "%s",\n  "sdk_version": "%s"\n}\n' "$IMAGE" "$version" >"$OUT"
echo "captured sdk $version for $IMAGE"
