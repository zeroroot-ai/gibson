package embedder

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// validateEndpoint rejects a tenant-supplied embedder BaseURL that resolves to
// an address class a hosted daemon should not reach (SSRF guard). When
// allowPrivate is true the guard is bypassed — the daemon sets that from
// security.allow_private_llm_endpoints for operators running a local/in-cluster
// embedder (the air-gap path).
//
// This mirrors the LLM provider SSRF guard (internal/engine/llm/providers/ssrf.go)
// but is kept local so this package stays dependency-light and does not import
// the llm package. Rejected classes: loopback, link-local (incl. cloud metadata
// 169.254.169.254), private RFC1918, IPv6 unique-local, and well-known metadata
// hostnames. Unresolvable hosts are allowed through — the request fails at call
// time and blocking here would break DNS-based load balancers.
func validateEndpoint(rawURL string, allowPrivate bool) error {
	if allowPrivate {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return types.NewError(ErrCodeInvalidConfig, fmt.Sprintf("invalid endpoint URL: %v", err))
	}
	host := u.Hostname()
	if host == "" {
		return types.NewError(ErrCodeInvalidConfig, "endpoint URL has no host")
	}

	switch strings.ToLower(host) {
	case "metadata.google.internal", "metadata", "instance-data":
		return types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("endpoint host %q is a cloud metadata service", host))
	}

	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	for _, ip := range addrs {
		if isBlockedIP(ip) {
			return types.NewError(ErrCodeInvalidConfig,
				fmt.Sprintf("endpoint host %q resolves to blocked address %s (set security.allow_private_llm_endpoints=true to override)", host, ip))
		}
	}
	return nil
}

// isBlockedIP returns true for loopback, link-local, private, or unique-local
// addresses plus the cloud metadata magic address.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	if ip.To16() != nil && ip.To4() == nil {
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
	}
	return false
}
