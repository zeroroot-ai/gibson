// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import "fmt"

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
