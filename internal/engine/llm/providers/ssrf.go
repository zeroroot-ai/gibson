package providers

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// validateLLMEndpoint rejects URLs that resolve to addresses that should not
// be reachable by a tenant-supplied LLM endpoint in hosted-SaaS mode. When
// allowPrivate is true the guard is bypassed — the daemon sets this from
// security.allow_private_llm_endpoints for dev-mode operators running local
// llamafile/vLLM servers from the same host as the daemon.
//
// Rejected address classes:
//   - Loopback (127.0.0.0/8, ::1)
//   - Link-local (169.254.0.0/16, fe80::/10) — includes AWS/GCP metadata
//   - Private RFC1918 (10/8, 172.16/12, 192.168/16)
//   - IPv6 unique-local (fc00::/7)
//   - Hardcoded cloud metadata hostnames (metadata.google.internal)
//
// Returns nil for unresolvable hostnames: the upstream call will fail anyway
// and blocking here would make DNS-based load balancers unreachable.
func validateLLMEndpoint(rawURL string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return llm.NewInvalidInputError("endpoint", fmt.Sprintf("invalid URL: %v", err))
	}
	host := u.Hostname()
	if host == "" {
		return llm.NewInvalidInputError("endpoint", "URL has no host")
	}

	// Block well-known metadata hostnames outright.
	lowerHost := strings.ToLower(host)
	switch lowerHost {
	case "metadata.google.internal", "metadata", "instance-data":
		return llm.NewInvalidInputError("endpoint",
			fmt.Sprintf("host %q is a cloud metadata service endpoint", host))
	}

	// Try DNS resolution; if it fails, let the caller discover at request time.
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	for _, ip := range addrs {
		if isBlockedIP(ip) {
			return llm.NewInvalidInputError("endpoint",
				fmt.Sprintf("host %q resolves to blocked address class %s (set security.allow_private_llm_endpoints=true to override)", host, ip))
		}
	}
	return nil
}

// isBlockedIP returns true for loopback, link-local, private, or unique-local
// addresses plus the EC2/GCP metadata magic addresses.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	// 169.254.169.254 is the AWS/EC2 instance metadata endpoint (also used by
	// GCP, Azure, DigitalOcean). net.IP.IsLinkLocalUnicast() should cover it
	// but we assert explicitly for readers and resilience.
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	// IPv6 unique-local fc00::/7
	if ip.To16() != nil && ip.To4() == nil {
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
	}
	return false
}
