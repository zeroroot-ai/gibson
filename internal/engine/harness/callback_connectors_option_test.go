// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
)

type stubConnectorClient struct{}

func (stubConnectorClient) ListConnectorTools(context.Context, string) ([]catalog.ToolEntry, error) {
	return nil, nil
}

func (stubConnectorClient) CallConnectorTool(context.Context, string, string, string, map[string]any) (any, error) {
	return nil, nil
}

// WithConnectors sets the MCP client of the callback service.
func TestWithConnectors_SetsTheClient(t *testing.T) {
	s := &HarnessCallbackService{}
	WithConnectors(stubConnectorClient{})(s)
	if _, ok := s.connectors.(stubConnectorClient); !ok {
		t.Fatalf("connectors = %#v; want the stub client", s.connectors)
	}
}
