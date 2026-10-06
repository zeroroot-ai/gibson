#!/usr/bin/env bash
# pin-plugin-image.sh — write the image of a plugin build into its catalog
# manifest (gibson#790). No person copies a digest.
#
# The catalog entry of a plugin is the manifest under
# internal/platform/componentcatalog/manifests/ with `kind: plugin` and
# `id: <plugin>`. This script replaces its `image:` value with the image the
# build pushed, and its `# plugin-source-tree:` line with the git tree hash of
# plugins/<plugin>/ that the image was built from. The image workflow compares
# that hash with the tree on main to decide whether the plugin changed, so an
# unchanged plugin is not rebuilt and opens no pin pull request.
#
# Usage:
#   bash scripts/pin-plugin-image.sh <plugin> <image@sha256:digest> <tree-hash>
#   bash scripts/pin-plugin-image.sh --tree <plugin>   # print the pinned tree hash
#   bash scripts/pin-plugin-image.sh --selftest
#
# A plugin with no catalog entry is not an error: the script says so and
# changes nothing. Exit codes: 0 done, 1 error, 2 usage.
set -euo pipefail

manifest_of() { # $1 plugin; prints the manifest path, or nothing
  local f dir="${MANIFEST_DIR:-internal/platform/componentcatalog/manifests}"
  for f in "$dir"/*.yaml; do
    if grep -qx 'kind: plugin' "$f" && grep -qx "id: $1" "$f"; then
      echo "$f"
      return
    fi
  done
}

pinned_tree() { # $1 plugin
  local f
  f=$(manifest_of "$1")
  [ -n "$f" ] || return 0
  sed -n 's/^# plugin-source-tree: \([0-9a-f]*\)$/\1/p' "$f"
}

pin() { # $1 plugin, $2 image@digest, $3 tree hash
  local f
  case "$2" in *@sha256:[0-9a-f]*) ;; *) echo "pin-plugin-image: $2 is not pinned by digest" >&2; return 1 ;; esac
  case "$3" in *[!0-9a-f]*|"") echo "pin-plugin-image: $3 is not a tree hash" >&2; return 1 ;; esac
  f=$(manifest_of "$1")
  if [ -z "$f" ]; then
    echo "pin-plugin-image: plugin $1 has no catalog entry; nothing to pin."
    return 0
  fi
  grep -qE '^  image: ' "$f" || { echo "pin-plugin-image: $f has no spec image line" >&2; return 1; }
  sed -i -E "s#^  image: .*#  image: $2#" "$f"
  if grep -q '^# plugin-source-tree: ' "$f"; then
    sed -i -E "s/^# plugin-source-tree: .*/# plugin-source-tree: $3/" "$f"
  else
    sed -i "0,/^id: /s//# plugin-source-tree: $3\nid: /" "$f"
  fi
  echo "pin-plugin-image: $f now runs $2 (tree $3)."
}

selftest() {
  tmp=$(mktemp -d); trap "rm -rf '$tmp'" EXIT
  printf '# A plugin.\nid: demo\nkind: plugin\nspec:\n  runtime: pod\n  image: ghcr.io/zeroroot-ai/old@sha256:aaa\n' > "$tmp/demo.yaml"
  printf 'id: demo\nkind: connector\nspec:\n  image: ghcr.io/zeroroot-ai/conn@sha256:bbb\n' > "$tmp/conn.yaml"
  MANIFEST_DIR=$tmp pin demo ghcr.io/zeroroot-ai/gibson-plugin-demo@sha256:ccc 0123abcd >/dev/null
  grep -qx '  image: ghcr.io/zeroroot-ai/gibson-plugin-demo@sha256:ccc' "$tmp/demo.yaml" || { echo "SELFTEST FAILED: image not pinned" >&2; return 1; }
  [ "$(MANIFEST_DIR=$tmp pinned_tree demo)" = 0123abcd ] || { echo "SELFTEST FAILED: tree not recorded" >&2; return 1; }
  grep -qx '  image: ghcr.io/zeroroot-ai/conn@sha256:bbb' "$tmp/conn.yaml" || { echo "SELFTEST FAILED: a connector changed" >&2; return 1; }
  MANIFEST_DIR=$tmp pin demo ghcr.io/zeroroot-ai/gibson-plugin-demo@sha256:ddd 4567 >/dev/null
  [ "$(grep -c '^# plugin-source-tree: ' "$tmp/demo.yaml")" = 1 ] || { echo "SELFTEST FAILED: a second pin added a second tree line" >&2; return 1; }
  if MANIFEST_DIR=$tmp pin demo ghcr.io/zeroroot-ai/gibson-plugin-demo:latest 4567 >/dev/null 2>&1; then
    echo "SELFTEST FAILED: a tag was accepted" >&2; return 1
  fi
  MANIFEST_DIR=$tmp pin none ghcr.io/zeroroot-ai/x@sha256:eee 89 >/dev/null || { echo "SELFTEST FAILED: a plugin with no entry failed" >&2; return 1; }
  echo "SELFTEST PASSED: pin, tree record, re-pin, tag refusal and no entry."
}

case "${1:-}" in
  --selftest) selftest ;;
  --tree) [ $# -eq 2 ] || { echo "usage: $0 --tree <plugin>" >&2; exit 2; }; pinned_tree "$2" ;;
  *) [ $# -eq 3 ] || { echo "usage: $0 <plugin> <image@digest> <tree-hash> | --tree <plugin> | --selftest" >&2; exit 2; }; pin "$@" ;;
esac
