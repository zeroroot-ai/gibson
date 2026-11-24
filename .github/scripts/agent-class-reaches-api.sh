#!/usr/bin/env bash
# Print the JSON patch ops that let the agent sandbox class reach the platform
# API on a kind cluster. The three KVM exit test profiles share this one script:
# the aaif-exit-cluster action, exit-test-bank and exit-test-sandboxed-dispatch.
#
# A sandbox resolves names only through setec.netpol.resolvers, and its network
# policy subtracts the private ranges from every egress rule. That is right on
# EKS, where api.<domain> is a public record. On kind the API host is a record
# of CoreDNS behind the ClusterIP of Envoy. A member then fails with
# "getaddrinfo ENOTFOUND api.localhost.zeroroot.ai" and never sends a heartbeat
# (run 45338071403). The agent class may reach the kube-dns pods on 53 and the
# Envoy pods on https by selector (setec#76), and it may use the kube-dns
# ClusterIP as its resolver.
#
# netpol.resolvers[0] applies to every sandbox class and replaces 1.1.1.1, so a
# tool class lookup tries kube-dns first and times out to 8.8.8.8.
#
# The Envoy pods carry app.kubernetes.io/name=gibson-workloads and
# app.kubernetes.io/component=envoy (the chart common labels). A selector on
# name=envoy matched nothing (run 35475259037).
#
# Usage:
#   agent-class-reaches-api.sh                 read the kube-dns ClusterIP with kubectl
#   agent-class-reaches-api.sh <cluster-ip>    use this ClusterIP
#   agent-class-reaches-api.sh --selftest      compare the output with the golden file
#
# Output: one line on stdout. It starts with a comma and holds the ops, so a
# caller appends it after the last op of an Argo application patch array. The
# test profile is the only caller.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ops() {
  local ip=$1
  local cls='gibson-workloads.setec.sandboxClasses.classes[2].spec.egressAllowSelectors'
  jq -nrc --arg ip "${ip}" --arg cls "${cls}" '
    [ {n:"gibson-workloads.setec.netpol.resolvers[0]", v:$ip, s:true},
      {n:($cls+"[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name"), v:"kube-system", s:true},
      {n:($cls+"[0].podSelector.matchLabels.k8s-app"), v:"kube-dns", s:true},
      {n:($cls+"[0].ports[0].protocol"), v:"UDP", s:true},
      {n:($cls+"[0].ports[0].port"), v:"53", s:false},
      {n:($cls+"[0].ports[1].protocol"), v:"TCP", s:true},
      {n:($cls+"[0].ports[1].port"), v:"53", s:false},
      {n:($cls+"[1].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name"), v:"gibson", s:true},
      {n:($cls+"[1].podSelector.matchLabels.app\\.kubernetes\\.io/name"), v:"gibson-workloads", s:true},
      {n:($cls+"[1].podSelector.matchLabels.app\\.kubernetes\\.io/component"), v:"envoy", s:true},
      {n:($cls+"[1].ports[0].port"), v:"https", s:true}
    ] | map({op:"add", path:"/spec/source/helm/parameters/-",
             value:({name:.n, value:.v} + (if .s then {forceString:true} else {} end))})
    | map(","+tojson) | join("")'
}

selftest() {
  local want got
  want=$(cat "${SCRIPT_DIR}/testdata/agent-class-reaches-api.golden")
  got=$(ops 10.96.0.10)
  if [ "${got}" != "${want}" ]; then
    echo "selftest FAIL: the ops differ from testdata/agent-class-reaches-api.golden" >&2
    return 1
  fi
  # The ops must parse as a JSON array once the leading comma is gone, with
  # the ClusterIP in the first one and 11 parameters in all.
  printf '[%s]' "${got#,}" | jq -e 'length == 11 and .[0].value.value == "10.96.0.10"' >/dev/null \
    || { echo "selftest FAIL: the ops are not 11 parameters with the ClusterIP first" >&2; return 1; }
  # A different ClusterIP must change only the resolver.
  got=$(ops 10.43.0.10)
  [ "${got}" = "${want//10.96.0.10/10.43.0.10}" ] \
    || { echo "selftest FAIL: the ClusterIP is not the only value that varies" >&2; return 1; }
  # An empty ClusterIP must be refused. This is the failing fixture.
  if "${BASH_SOURCE[0]}" "" >/dev/null 2>&1; then
    echo "selftest FAIL: an empty ClusterIP was accepted" >&2
    return 1
  fi
  echo "selftest PASS"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit
fi

if [ "$#" -ge 1 ]; then
  CLUSTER_IP=$1
else
  CLUSTER_IP=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}')
fi
[ -n "${CLUSTER_IP}" ] || { echo "::error::no kube-dns ClusterIP to hand the sandboxes" >&2; exit 1; }
echo "the agent class resolves through kube-dns at ${CLUSTER_IP} and may reach the kube-dns and Envoy pods" >&2
ops "${CLUSTER_IP}"
