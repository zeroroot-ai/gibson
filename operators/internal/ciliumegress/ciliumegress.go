// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package ciliumegress builds the egress rules of a CiliumNetworkPolicy from
// a host list of the catalog ("api.github.com:443"). A Kubernetes
// NetworkPolicy matches addresses and labels and cannot name a host, so an
// operator writes one CiliumNetworkPolicy for each workload with a host list
// (ADR-0114, ADR-0136, D76). The connector operator and the tenant operator
// both use this one builder.
package ciliumegress

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// APIVersion is the API version of the CiliumNetworkPolicy resource.
	APIVersion = "cilium.io/v2"
	// Kind is the kind of the CiliumNetworkPolicy resource.
	Kind = "CiliumNetworkPolicy"
	// DNSNamespace is the namespace of kube-dns.
	DNSNamespace = "kube-system"

	defaultPort = 443
)

// ErrBadEntry reports a host list entry that is not host or host:port.
var ErrBadEntry = errors.New("an egressAllow entry is not host or host:port")

// NewPolicy returns an empty CiliumNetworkPolicy object.
func NewPolicy() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(APIVersion)
	u.SetKind(Kind)
	return u
}

// ParseEntry splits a host list entry ("api.github.com:443",
// "*.slack.com:443" or "api.osv.dev") into its host and port. The port is 443
// when the entry names none.
func ParseEntry(entry string) (host string, port int, err error) {
	entry = strings.TrimSpace(entry)
	host, portStr, splitErr := net.SplitHostPort(entry)
	if splitErr != nil {
		host, portStr = entry, strconv.Itoa(defaultPort)
	}
	port, convErr := strconv.Atoi(portStr)
	if host == "" || strings.ContainsAny(host, ":/ ") || convErr != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%w: %q", ErrBadEntry, entry)
	}
	return host, port, nil
}

// Rules returns the egress rules for a host list. The first rule permits DNS
// to kube-dns with a DNS rule, because Cilium learns the address of a host
// name only from a lookup that it sees. Each next rule permits one host on
// its port over TCP. A host with "*" is a pattern.
func Rules(entries []string) ([]interface{}, error) {
	rules := []interface{}{map[string]interface{}{
		"toEndpoints": []interface{}{map[string]interface{}{
			"matchLabels": map[string]interface{}{
				"io.kubernetes.pod.namespace": DNSNamespace,
				"k8s-app":                     "kube-dns",
			},
		}},
		"toPorts": []interface{}{map[string]interface{}{
			"ports": []interface{}{map[string]interface{}{"port": "53", "protocol": "ANY"}},
			"rules": map[string]interface{}{
				"dns": []interface{}{map[string]interface{}{"matchPattern": "*"}},
			},
		}},
	}}
	for _, entry := range entries {
		host, port, err := ParseEntry(entry)
		if err != nil {
			return nil, err
		}
		fqdn := map[string]interface{}{"matchName": host}
		if strings.Contains(host, "*") {
			fqdn = map[string]interface{}{"matchPattern": host}
		}
		rules = append(rules, map[string]interface{}{
			"toFQDNs": []interface{}{fqdn},
			"toPorts": []interface{}{map[string]interface{}{
				"ports": []interface{}{map[string]interface{}{"port": strconv.Itoa(port), "protocol": "TCP"}},
			}},
		})
	}
	return rules, nil
}

// DeniedRanges are the address ranges that a workload with a host list must
// never reach: the private ranges of RFC 1918, link-local (with the cloud
// metadata address 169.254.169.254), loopback, CGNAT, unique local, and the
// unspecified addresses. A host name of the list can resolve to one of them
// (DNS rebinding), so the allow rules alone do not stop it (review B3).
var DeniedRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"127.0.0.0/8",
	"100.64.0.0/10",
	"0.0.0.0/8",
	"fc00::/7",
	"fe80::/10",
	"::1/128",
	"::/128",
}

// DenyRules returns the egressDeny rules of a workload with a host list: one
// rule that denies DeniedRanges and the cluster ranges that the caller gives
// (the pod and the service CIDRs of the install).
//
// A Cilium deny rule wins over every allow rule, a toFQDNs allow too
// (docs.cilium.io, "Deny Policies"). A deny rule cannot name a host, but it
// can name a CIDR. The address that a toFQDNs name resolves to is then denied
// when it is in one of these ranges, whatever the name is. Cilium before
// 1.14.16, 1.15.10 and 1.16.3 can drop a CIDR deny when a narrower CIDR allow
// exists (CVE-2024-47825). This policy has no CIDR allow, and an install must
// run a fixed version.
func DenyRules(clusterCIDRs []string) ([]interface{}, error) {
	cidrs := make([]interface{}, 0, len(DeniedRanges)+len(clusterCIDRs))
	for _, c := range append(append([]string(nil), DeniedRanges...), clusterCIDRs...) {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrBadCIDR, c)
		}
		cidrs = append(cidrs, map[string]interface{}{"cidr": n.String()})
	}
	return []interface{}{map[string]interface{}{"toCIDRSet": cidrs}}, nil
}

// ErrBadCIDR reports a cluster range that is not a CIDR.
var ErrBadCIDR = errors.New("a cluster range is not a CIDR")
