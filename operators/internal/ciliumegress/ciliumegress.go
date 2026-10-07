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
