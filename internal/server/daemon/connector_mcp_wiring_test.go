// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
)

// The daemon builds one MCP client, and with no SPIFFE JWT source a request
// carries no token.
func TestConnectorMCPClient_OneClientAndNoTokenWithNoSource(t *testing.T) {
	d := testDaemonForRegistry(t)
	if d.connectorMCPClient() == nil || d.connectorMCPClient() != d.connectorMCPClient() {
		t.Fatal("the daemon must build exactly one MCP client")
	}
	tok, err := d.connectorProxyToken(context.Background())
	if err != nil || tok != "" {
		t.Fatalf("token = %q, err = %v; want no token and no error", tok, err)
	}
}
