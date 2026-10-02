#!/usr/bin/env bash
# check-first-party-tags.sh — CI guard: every first-party module go.mod
# requires exists as a tag in its repository.
#
# Spec: gibson#196.
#
# THE PROBLEM
# -----------
# go.mod required github.com/zeroroot-ai/setec v0.114.0 and testfixtures
# v0.2.0 for weeks after the 2026-09-06 history reset deleted both tags.
# proxy.golang.org had cached them, so CI passed, and every machine with
# GOPRIVATE=github.com/zeroroot-ai/* (the shape a contributor with private
# access uses) failed `go mod tidy` with "unknown revision". The module set
# depended on a cache nobody controls: the day the proxy evicted those
# versions, every clean build would have failed at module download.
#
# THE RULE
# --------
# For every `github.com/zeroroot-ai/<repo>[/<subdir>] vX.Y.Z` line in the
# go.mod require blocks, the tag `vX.Y.Z` (or `<subdir>/vX.Y.Z` for a nested
# module) must exist in github.com/zeroroot-ai/<repo>. A pseudo-version
# (vX.Y.Z-0.YYYYMMDDhhmmss-<hash>) must name a commit that exists. The
# lookup goes through the GitHub API with `gh`, so a private repository
# resolves with the workflow token the same way a public one does.
#
# Self-test mode (--selftest): a synthetic go.mod that requires a version no
# tag carries must fail, and one that names a real tag must pass.
#
# Exit 0 = every first-party requirement resolves; 1 = one does not.
set -euo pipefail

GO_MOD="${GO_MOD:-go.mod}"
ORG="zeroroot-ai"

tag_exists() { # repo tag
  gh api "repos/${ORG}/$1/git/ref/tags/$2" --silent >/dev/null 2>&1
}
commit_exists() { # repo sha-prefix
  gh api "repos/${ORG}/$1/commits/$2" --silent >/dev/null 2>&1
}

check() {
  local mod="$1" fail=0 n=0
  # Lines like `\tgithub.com/zeroroot-ai/setec v0.118.0` or
  # `\tgithub.com/zeroroot-ai/sdk/foo v1.2.3 // indirect`, inside or outside
  # a require block. Replace directives are forbidden by a separate guard.
  while read -r path version _; do
    [[ "$path" == github.com/${ORG}/* ]] || continue
    n=$((n + 1))
    local rest="${path#github.com/${ORG}/}" repo subdir tag
    repo="${rest%%/*}"
    subdir=""
    [[ "$rest" == */* ]] && subdir="${rest#*/}"
    if [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-[0-9.]*[0-9]{14}-([0-9a-f]{12})$ ]]; then
      local sha="${BASH_REMATCH[1]}"
      if commit_exists "$repo" "$sha"; then
        echo "[check-first-party-tags] ok    $path $version (commit $sha)"
      else
        echo "[check-first-party-tags] FAIL  $path $version: commit $sha is not in github.com/${ORG}/${repo}" >&2
        fail=1
      fi
      continue
    fi
    tag="$version"
    [[ -n "$subdir" ]] && tag="${subdir}/${version}"
    if tag_exists "$repo" "$tag"; then
      echo "[check-first-party-tags] ok    $path $version"
    else
      echo "[check-first-party-tags] FAIL  $path $version: tag $tag does not exist in github.com/${ORG}/${repo}. The version resolves only while the module proxy keeps a copy. Require a version the repository carries." >&2
      fail=1
    fi
  done < <(grep -E "^\s*(require\s+)?github\.com/${ORG}/[A-Za-z0-9._/-]+ v[0-9]" "$mod" | sed -E 's/^\s*(require\s+)?//')
  if [[ "$n" -eq 0 ]]; then
    echo "[check-first-party-tags] FAIL  $mod names no github.com/${ORG} module; the guard measured nothing" >&2
    return 1
  fi
  return "$fail"
}

if [[ "${1:-}" == "--selftest" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  printf 'module x\n\ngo 1.27\n\nrequire github.com/%s/setec v0.0.1-nonexistent\n' "$ORG" >"$tmp/bad.mod"
  if GO_MOD="$tmp/bad.mod" check "$tmp/bad.mod" >/dev/null 2>&1; then
    echo "selftest FAIL: a version with no tag passed the guard" >&2; exit 1
  fi
  echo "selftest PASS: a version with no tag fails the guard"
  real="$(grep -E "^\s*github\.com/${ORG}/setec v" "$GO_MOD" | head -1 | sed -E 's/^\s+//')"
  [[ -n "$real" ]] || { echo "selftest FAIL: $GO_MOD requires no github.com/${ORG}/setec" >&2; exit 1; }
  printf 'module x\n\ngo 1.27\n\nrequire %s\n' "$real" >"$tmp/good.mod"
  if ! check "$tmp/good.mod" >/dev/null 2>&1; then
    echo "selftest FAIL: the real setec requirement (${real}) did not pass the guard" >&2; exit 1
  fi
  echo "selftest PASS: a version with a tag passes the guard"
  exit 0
fi

check "$GO_MOD"
echo "[check-first-party-tags] every first-party requirement in $GO_MOD exists as a tag"
