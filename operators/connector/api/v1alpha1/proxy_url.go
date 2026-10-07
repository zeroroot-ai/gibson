// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"fmt"
	"regexp"
)

// ProxyPort is the port that the ToolHive proxy Service of a connector
// exposes.
const ProxyPort = 8080

// ProxyAudience is the audience of the JWT-SVID that the daemon presents to
// the ToolHive proxy of a connector (ADR-0065, D22). The operator binds the
// proxy to this audience, and the daemon mints its token for it. It is one
// constant so that the two can never disagree.
const ProxyAudience = "gibson-connector-proxy"

// ProxyURL returns the in-cluster MCP address of the connector instance name
// in namespace. The operator writes it to Status.ProxyURL, and the daemon,
// the one MCP client (ADR-0065), dials it. It is one function so that the two
// can never disagree.
func ProxyURL(name, namespace string) string {
	return fmt.Sprintf("http://mcp-%s-proxy.%s.svc.cluster.local:%d/mcp", name, namespace, ProxyPort)
}

// proxyHost matches the host of a connector proxy Service in each form that
// cluster DNS resolves: mcp-<name>-proxy, with or without the namespace and
// svc parts, and with any cluster domain after svc.
var proxyHost = regexp.MustCompile(`(?i)^mcp-[a-z0-9-]+-proxy(\.[a-z0-9-]+(\.svc(\.[a-z0-9-]+)*)?)?\.?$`)

// IsProxyHost reports whether host names the proxy Service of a connector
// (the host of ProxyURL). Only the daemon calls a connector (ADR-0065), so no
// sandbox egress rule and no catalog egress entry may name one (gibson#723).
//
// It is a second layer. The network policy of the cluster (D76) and the
// caller identity check of the proxy are the controls. The sandbox scope
// also compares the resolved addresses of the proxies of the tenant.
func IsProxyHost(host string) bool {
	return proxyHost.MatchString(host)
}
