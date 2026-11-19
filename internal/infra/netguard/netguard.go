// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package netguard supplies connect-time egress controls for outbound HTTP
// clients that talk to tenant-supplied endpoints (LLM base URLs, embedder
// endpoints).
//
// The control is a net.Dialer Control hook. Control runs after DNS resolution
// and before connect(2), on the concrete address the kernel is about to reach,
// for EVERY connection the client opens. That placement is what makes it
// load-bearing:
//
//   - URL-shape or resolve-then-check validation is a TOCTOU window: the name
//     can resolve to a public address at validation time and to 169.254.169.254
//     at connect time (DNS rebinding).
//   - Redirects open new connections that a one-shot URL check never sees, so a
//     public endpoint answering 302 http://169.254.169.254/ defeats it.
//
// A Control hook has neither gap: every hop, every retry, every rebind lands on
// the same check.
//
// allowPrivate is the single dev/air-gap escape hatch and comes from the
// existing security.allow_private_llm_endpoints daemon config knob. It is off
// by default; nothing here invents a new permissive default.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"
)

// BlockedAddressError reports a connection refused by the egress guard. It is
// returned from the dialer, so callers see it wrapped in *net.OpError /
// *url.Error exactly like any other dial failure.
type BlockedAddressError struct {
	// Addr is the resolved address the client tried to reach ("ip:port").
	Addr string
	// Class names the blocked address class, for operator diagnostics.
	Class string
	// Hint tells the reader what to change. It is the text in the brackets
	// of the message. A caller that has its own setting passes its own hint.
	Hint string
}

// LLMEndpointHint is the hint of a refusal for a model or embedder endpoint.
// It is the hint that Dialer, Transport and HTTPClient use.
const LLMEndpointHint = "set security.allow_private_llm_endpoints=true to permit private endpoints"

func (e *BlockedAddressError) Error() string {
	msg := fmt.Sprintf("netguard: refusing to connect to %s: %s address", e.Addr, e.Class)
	if e.Hint == "" {
		return msg
	}
	return msg + " (" + e.Hint + ")"
}

// nat64Prefix is the well-known NAT64 prefix (RFC 6052). An address inside it
// embeds an IPv4 destination in its low 32 bits, so a translated 169.254.169.254
// would otherwise sail past every IPv6 predicate.
var nat64Prefix = net.IPNet{
	IP:   net.IP{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	Mask: net.CIDRMask(96, 128),
}

// cgnat is RFC 6598 carrier-grade NAT space (100.64.0.0/10). Not covered by
// net.IP.IsPrivate, but routinely used for internal/cluster addressing.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// reservedIPv4 lists further non-public IPv4 ranges that are neither RFC1918
// nor link-local, but which a hosted daemon still has no business reaching.
var reservedIPv4 = []struct {
	class string
	cidr  net.IPNet
}{
	{"this-network", net.IPNet{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)}},
	{"ietf-protocol-assignment", net.IPNet{IP: net.IPv4(192, 0, 0, 0), Mask: net.CIDRMask(24, 32)}},
	{"benchmarking", net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}},
	{"reserved", net.IPNet{IP: net.IPv4(240, 0, 0, 0), Mask: net.CIDRMask(4, 32)}},
}

// BlockedClass names the blocked address class an IP belongs to, or "" when the
// address is a routable public destination the daemon may reach.
//
// Blocked: unspecified (0.0.0.0, ::), loopback (127/8, ::1), link-local
// (169.254/16 — including the 169.254.169.254 cloud metadata service — and
// fe80::/10), RFC1918 private (10/8, 172.16/12, 192.168/16) plus IPv6
// unique-local fc00::/7, CGNAT 100.64/10, multicast and broadcast, the NAT64
// well-known prefix when it embeds a blocked IPv4, and the reserved IPv4 ranges
// above.
func BlockedClass(ip net.IP) string {
	if ip == nil {
		return "unparseable"
	}
	// Normalise IPv4-in-IPv6 (::ffff:127.0.0.1) so the IPv4 predicates apply.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 (AWS/GCP/Azure/DO instance metadata) lives here.
		return "link-local"
	case ip.IsPrivate():
		// Covers RFC1918 and IPv6 unique-local fc00::/7.
		return "private"
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "multicast"
	}

	if len(ip) == net.IPv4len {
		if cgnat.Contains(ip) {
			return "carrier-grade-nat"
		}
		if ip.Equal(net.IPv4bcast) {
			return "broadcast"
		}
		for _, r := range reservedIPv4 {
			if r.cidr.Contains(ip) {
				return r.class
			}
		}
		return ""
	}

	// IPv6 from here on.
	if nat64Prefix.Contains(ip) {
		// Re-check the embedded IPv4 destination.
		if embedded := net.IPv4(ip[12], ip[13], ip[14], ip[15]); BlockedClass(embedded) != "" {
			return "nat64-embedded-" + BlockedClass(embedded)
		}
	}
	return ""
}

// ControlWithHint returns the net.Dialer Control hook. address is the
// post-resolution "ip:port" the kernel is about to connect to. Its refusals carry hint. An empty
// hint gives a refusal with no hint.
func ControlWithHint(hint string) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// Fail closed: an address we cannot parse is an address we cannot vet.
			return &BlockedAddressError{Addr: address, Class: "unparseable", Hint: hint}
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// Control always receives a literal IP; a name here means something
			// resolved outside our view. Fail closed.
			return &BlockedAddressError{Addr: address, Class: "unresolved", Hint: hint}
		}
		if class := BlockedClass(ip); class != "" {
			return &BlockedAddressError{Addr: address, Class: class, Hint: hint}
		}
		return nil
	}
}

// Dialer returns a net.Dialer with the egress guard installed. When
// allowPrivate is true the guard is omitted — the daemon sets that from
// security.allow_private_llm_endpoints for operators running an in-cluster or
// air-gapped model server.
func Dialer(allowPrivate bool) *net.Dialer {
	return DialerWithHint(allowPrivate, LLMEndpointHint)
}

// DialerWithHint is Dialer with the hint of the refusals set by the caller.
func DialerWithHint(allowPrivate bool, hint string) *net.Dialer {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !allowPrivate {
		d.Control = ControlWithHint(hint)
	}
	return d
}

// Transport returns an *http.Transport whose dialer enforces the egress guard.
// Callers must not replace DialContext afterwards.
func Transport(allowPrivate bool) *http.Transport {
	return TransportWithHint(allowPrivate, LLMEndpointHint)
}

// TransportWithHint is Transport with the hint of the refusals set by the caller.
func TransportWithHint(allowPrivate bool, hint string) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = DialerWithHint(allowPrivate, hint).DialContext
	// The guard runs per-connection, so a pooled connection to an address that
	// was legal when opened stays legal — addresses do not change under a live
	// TCP connection. Keep the stock pool sizing.
	return tr
}

// HTTPClient returns an *http.Client that refuses, at connect time, to reach
// any blocked address class — on the initial request and on every redirect hop.
func HTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(allowPrivate),
	}
}

// Resolver looks up the addresses of a host name. *net.Resolver satisfies it.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// hostRefusedText is the only text that a client sees when CheckHost refuses a host.
const hostRefusedText = "the host does not resolve to a public address"

// HostRefusedError reports that CheckHost refused a host. Error() is safe to send
// to an API client: it holds no address, no address class and no resolver detail.
// The detail is for the daemon log. A caller reads it with Detail, and it does not
// pass the detail to a client. The error does not unwrap to the detail, so errors.Is
// and errors.As on the error never reach it.
type HostRefusedError struct {
	hint   string
	detail string
}

// Error returns the fixed text and the hint of the setting, when there is one.
func (e *HostRefusedError) Error() string {
	if e.hint == "" {
		return hostRefusedText
	}
	return hostRefusedText + " (" + e.hint + ")"
}

// Detail returns the address, its class or the resolver error. It is for the log.
func (e *HostRefusedError) Detail() string { return e.detail }

// CheckHost resolves host and refuses it when ANY address is in a blocked
// class. It is a check at one point in time, for example at registration. It is
// NOT a connect-time control: the name can resolve to another address later, so
// the code that makes the connection must use ControlWithHint or a guard of its own.
// An IP literal is checked without a lookup.
//
// A refusal is a *HostRefusedError. A blocked address, a failed lookup and a host with
// no address all give the same safe text, with hint. The text names no address, class
// or resolver, so a tenant cannot use the refusal to probe the network of the daemon.
func CheckHost(ctx context.Context, r Resolver, host, hint string) error {
	refuse := func(detail string) error { return &HostRefusedError{hint: hint, detail: detail} }
	if ip := net.ParseIP(host); ip != nil {
		if class := BlockedClass(ip); class != "" {
			return refuse((&BlockedAddressError{Addr: ip.String(), Class: class}).Error())
		}
		return nil
	}
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return refuse(fmt.Sprintf("netguard: resolve %s: %v", host, err))
	}
	if len(addrs) == 0 {
		return refuse(fmt.Sprintf("netguard: resolve %s: no address", host))
	}
	for _, a := range addrs {
		if class := BlockedClass(a.IP); class != "" {
			return refuse((&BlockedAddressError{Addr: a.IP.String(), Class: class}).Error())
		}
	}
	return nil
}

// RedactBlocked prepares an error for an API client. When the chain holds a
// *BlockedAddressError, the connect-time guard refused the connection. The text of
// that error, and the text of the *net.OpError that wraps it, name the address that
// the host resolved to. A tenant that controls the host name could read internal
// addresses from it. RedactBlocked then writes the detail to the daemon log and
// returns a *HostRefusedError, whose text is fixed. An error with no refusal in its
// chain comes back unchanged. A caller that returns a dial error to a client passes
// it through RedactBlocked first.
func RedactBlocked(ctx context.Context, err error) error {
	var blocked *BlockedAddressError
	if !errors.As(err, &blocked) {
		return err
	}
	slog.WarnContext(ctx, "connection refused by the egress guard", "detail", err.Error())
	return &HostRefusedError{hint: blocked.Hint, detail: err.Error()}
}
