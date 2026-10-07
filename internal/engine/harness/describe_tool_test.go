// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	sdktypes "github.com/zeroroot-ai/sdk/types"
)

// registeredNmap is the registry entry of a tool as the SDK registers it.
func registeredNmap() component.ComponentInfo {
	return component.ComponentInfo{
		Kind: "tool", Name: "nmap", Version: "7.95",
		Metadata: map[string]string{
			"description":         "port scanner",
			"tags":                "network, scanner,,recon",
			"input_message_type":  "gibson.tools.nmap.v1.Request",
			"output_message_type": "gibson.tools.nmap.v1.Response",
			"capabilities":        `{"has_sudo":true,"blocked_args":["-sS"]}`,
		},
	}
}

func describeHarness(adapter component.ComponentDiscovery) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:          slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:          noop.NewTracerProvider().Tracer("test"),
		registryAdapter: adapter,
	}
}

// The descriptor of a tool comes from its registry entry. No tool is dialled
// (gibson#813).
func TestGetToolDescriptor_ReadsTheRegistryEntry(t *testing.T) {
	h := describeHarness(&MockRegistryAdapter{
		DescribeToolFn: func(context.Context, string) (component.ComponentInfo, error) { return registeredNmap(), nil },
	})
	desc, err := h.GetToolDescriptor(context.Background(), "nmap")
	require.NoError(t, err)
	assert.Equal(t, "nmap", desc.Name)
	assert.Equal(t, "port scanner", desc.Description)
	assert.Equal(t, "7.95", desc.Version)
	assert.Equal(t, []string{"network", "scanner", "recon"}, desc.Tags)
	assert.Equal(t, "gibson.tools.nmap.v1.Request", desc.InputProtoType)
	assert.Equal(t, "gibson.tools.nmap.v1.Response", desc.OutputProtoType)
	assert.Equal(t, "port scanner", desc.Metadata["description"])
}

func TestGetToolDescriptor_UnknownToolFails(t *testing.T) {
	h := describeHarness(&MockRegistryAdapter{
		DescribeToolFn: func(context.Context, string) (component.ComponentInfo, error) {
			return component.ComponentInfo{}, errors.New("no such tool")
		},
	})
	_, err := h.GetToolDescriptor(context.Background(), "nope")
	require.Error(t, err)
}

// The capabilities of a tool come from the JSON it registered.
func TestGetToolCapabilities_ReadsTheRegistryEntry(t *testing.T) {
	h := describeHarness(&MockRegistryAdapter{
		DescribeToolFn: func(context.Context, string) (component.ComponentInfo, error) { return registeredNmap(), nil },
	})
	caps, err := h.GetToolCapabilities(context.Background(), "nmap")
	require.NoError(t, err)
	require.NotNil(t, caps)
	assert.True(t, caps.HasSudo)
	assert.Equal(t, []string{"-sS"}, caps.BlockedArgs)

	h = describeHarness(&MockRegistryAdapter{
		DescribeToolFn: func(context.Context, string) (component.ComponentInfo, error) {
			return component.ComponentInfo{Name: "plain"}, nil
		},
	})
	caps, err = h.GetToolCapabilities(context.Background(), "plain")
	require.NoError(t, err)
	assert.Nil(t, caps, "a tool that declared no capabilities has none")

	h = describeHarness(&MockRegistryAdapter{
		DescribeToolFn: func(context.Context, string) (component.ComponentInfo, error) {
			return component.ComponentInfo{}, errors.New("no such tool")
		},
	})
	_, err = h.GetToolCapabilities(context.Background(), "nope")
	require.Error(t, err)
}

// GetAllToolCapabilities reads the capabilities that ListTools parsed, and
// leaves out a tool that declared none.
func TestGetAllToolCapabilities_ReadsTheListedTools(t *testing.T) {
	h := describeHarness(&MockRegistryAdapter{
		ListToolsFn: func(context.Context) ([]component.ToolInfo, error) {
			return []component.ToolInfo{
				{Name: "nmap", Capabilities: &sdktypes.Capabilities{HasRoot: true}},
				{Name: "plain"},
			}, nil
		},
	})
	all, err := h.GetAllToolCapabilities(context.Background())
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.True(t, all["nmap"].HasRoot)
}
