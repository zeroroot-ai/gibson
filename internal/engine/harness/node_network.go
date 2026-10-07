// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/sdk/auth"
)

// The network scope of a mission node (owner decision S6, gibson#865).
//
// By default the sandbox of a node reaches only the targets bound to that
// node, plus the daemon and its model provider. A node that the mission
// author marks `research` is unrestricted. A tool that runs inside a node
// gets the network of that node. An empty list means no egress.
//
// No rule names the proxy of a connector: the daemon is the one caller of a
// connector (ADR-0065), so an agent has no network path to one (gibson#723).

// allPorts is every port of a target, for TCP and for UDP. A target is
// reached on the ports that the work needs, and the scope does not guess
// them.
var allPorts = []sandboxed.PortRange{
	{Protocol: "TCP", Port: 1, EndPort: 65535},
	{Protocol: "UDP", Port: 1, EndPort: 65535},
}

// nodeNetworkScope returns the setec network mode and the allow list of a
// sandbox in the node n. extra holds the addresses that the sandbox needs
// beside the targets, for example the callback endpoint of the daemon. An
// address that cannot be read is left out: the scope never widens on a bad
// value.
func nodeNetworkScope(n *agent.NodeNetwork, guard proxyGuard, extra ...string) (mode string, rules []sandboxed.EgressRule) {
	if n.Research {
		return sandboxed.NetworkModeExternalOnly, nil
	}
	for _, target := range n.Targets {
		if rule, ok := egressRuleForTarget(target); ok && !guard.blocks(rule) {
			rules = append(rules, rule)
		}
	}
	for _, addr := range append(append([]string(nil), n.ProviderHosts...), extra...) {
		if rule, ok := egressRuleForService(addr); ok && !guard.blocks(rule) {
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return sandboxed.NetworkModeNone, nil
	}
	return sandboxed.NetworkModeAllowList, rules
}

// egressRuleForTarget reads one bound target: a CIDR, a URL, a host and a
// port, or a host. A target with no port is reachable on each port.
func egressRuleForTarget(target string) (sandboxed.EgressRule, bool) {
	target = strings.TrimSpace(target)
	if target == "" || target == "*" {
		return sandboxed.EgressRule{}, false
	}
	if _, block, err := net.ParseCIDR(target); err == nil {
		return sandboxed.EgressRule{CIDR: block.String(), Ports: allPorts}, true
	}
	host, port, ok := splitAddress(target)
	if !ok {
		return sandboxed.EgressRule{}, false
	}
	if port == 0 {
		return sandboxed.EgressRule{Host: host, Ports: allPorts}, true
	}
	return sandboxed.EgressRule{Host: host, Port: port}, true
}

// egressRuleForService reads the address of a service that the sandbox
// calls, for example the daemon or the model provider. A service with no
// port is reached on 443.
func egressRuleForService(addr string) (sandboxed.EgressRule, bool) {
	host, port, ok := splitAddress(strings.TrimSpace(addr))
	if !ok {
		return sandboxed.EgressRule{}, false
	}
	if port == 0 {
		port = 443
	}
	return sandboxed.EgressRule{Host: host, Port: port}, true
}

// splitAddress reads "scheme://host[:port]/path", "host:port" or "host". A
// port of 0 means that the address names no port.
func splitAddress(addr string) (host string, port uint32, ok bool) {
	if addr == "" || addr == "*" {
		return "", 0, false
	}
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil || u.Hostname() == "" {
			return "", 0, false
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			n, perr := strconv.ParseUint(p, 10, 16)
			if perr != nil || n == 0 {
				return "", 0, false
			}
			return host, uint32(n), true
		}
		switch u.Scheme {
		case "https":
			return host, 443, true
		case "http":
			return host, 80, true
		}
		return host, 0, true
	}
	if h, p, err := net.SplitHostPort(addr); err == nil {
		n, perr := strconv.ParseUint(p, 10, 16)
		if h == "" || perr != nil || n == 0 {
			return "", 0, false
		}
		return h, uint32(n), true
	}
	if strings.ContainsAny(addr, "/ ") {
		return "", 0, false
	}
	return addr, 0, true
}

// proxyGuard refuses an egress rule that reaches the proxy of a connector of
// the tenant (gibson#723). addrs holds the resolved addresses of those
// proxies. A rule is refused when its host has the name of a proxy, when its
// IP or CIDR holds a proxy address, or when its host resolves to one. It is a
// second layer: the network policy of the cluster (D76) is the control.
type proxyGuard struct {
	addrs  []netip.Addr
	lookup func(host string) []netip.Addr
}

// blocks reports whether rule reaches a connector proxy.
func (g proxyGuard) blocks(rule sandboxed.EgressRule) bool {
	if rule.CIDR != "" {
		p, err := netip.ParsePrefix(rule.CIDR)
		if err != nil {
			return true
		}
		for _, a := range g.addrs {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if connectorv1alpha1.IsProxyHost(rule.Host) {
		return true
	}
	if ip, err := netip.ParseAddr(rule.Host); err == nil {
		return g.holds(ip)
	}
	if g.lookup != nil {
		for _, ip := range g.lookup(rule.Host) {
			if g.holds(ip) {
				return true
			}
		}
	}
	return false
}

func (g proxyGuard) holds(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, a := range g.addrs {
		if a.Unmap() == ip {
			return true
		}
	}
	return false
}

// proxyLookupTimeout bounds one name resolution of the guard.
const proxyLookupTimeout = 2 * time.Second

// lookupNetIP resolves a host name. Tests replace it.
var lookupNetIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// connectorProxyGuard builds the guard for the tenant of ctx. A proxy that
// does not resolve (a connector the tenant did not enable) adds no address.
func connectorProxyGuard(ctx context.Context) proxyGuard {
	lookup := func(host string) []netip.Addr {
		lctx, cancel := context.WithTimeout(ctx, proxyLookupTimeout)
		defer cancel()
		addrs, err := lookupNetIP(lctx, host)
		if err != nil {
			return nil
		}
		return addrs
	}
	g := proxyGuard{lookup: lookup}
	if tenant := auth.TenantStringFromContext(ctx); tenant != "" {
		for _, host := range component.ConnectorProxyHosts(tenant) {
			g.addrs = append(g.addrs, lookup(host)...)
		}
	}
	return g
}
