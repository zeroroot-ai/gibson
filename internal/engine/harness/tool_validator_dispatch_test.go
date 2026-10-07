// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The point of gibson#625: the two metrics move on a real dispatch.
//
// Before this, ToolValidator had no production caller at all, so
// gibson_tool_discovery_compliance_total and gibson_tool_extraction_skipped_total
// were exported and ALWAYS ZERO — a dashboard or alert built on either read as
// "nothing was ever skipped", which is indistinguishable from "everything is
// fine".
//
// Both tests dispatch through CallToolProto rather than calling the validator
// directly, because "is it wired" is the thing that was wrong.

// dispatchToolCall runs one CallToolProto against a tool whose handler is
// `fill`, and returns the response. toolName is what the catalog is asked
// about, so it decides whether the response is expected to carry a
// DiscoveryResult.
func dispatchToolCall(t *testing.T, toolName, pkg, fds string, fill func(proto.Message)) *harnesspb.CallToolProtoResponse {
	t.Helper()

	mockHarness := &mockHarnessWithResolver{
		toolDescriptors: map[string]*ToolDescriptor{
			toolName: {
				Name:            toolName,
				InputProtoType:  pkg + ".ToolInput",
				OutputProtoType: pkg + ".ToolOutput",
				Metadata:        map[string]string{"file_descriptor_set": fds},
			},
		},
		toolHandler: func(_ context.Context, _ string, _ proto.Message, response proto.Message) error {
			fill(response)
			return nil
		},
	}

	registry := NewCallbackHarnessRegistry()
	service := NewHarnessCallbackServiceWithRegistry(slog.New(slog.DiscardHandler), registry, testEventBus())
	const missionID, agentName = "mission-625", "agent-625"
	registry.Register(missionID, agentName, mockHarness)

	resp, err := service.CallToolProto(testCtxWithTenant(), &harnesspb.CallToolProtoRequest{
		Context: &harnesspb.ContextInfo{
			TaskId:       "task-625",
			AgentName:    agentName,
			MissionId:    missionID,
			MissionRunId: "run-625",
		},
		Name:       toolName,
		InputType:  pkg + ".ToolInput",
		InputJson:  []byte(`{"query":"q"}`),
		OutputType: pkg + ".ToolOutput",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error, "dispatch failed: %v", resp.Error)
	return resp
}

// setResult fills the ordinary output fields, leaving field 100 empty.
func setResult(response proto.Message) {
	refl := response.ProtoReflect()
	refl.Set(refl.Descriptor().Fields().ByName("result"), protoreflect.ValueOfString("ok"))
	refl.Set(refl.Descriptor().Fields().ByName("count"), protoreflect.ValueOfInt32(1))
}

// A discovery tool whose response carries NO DiscoveryResult is recorded as
// non-compliant and counted as skipped, with a named reason. That is how a
// parser that quietly stopped emitting graph nodes becomes visible.
func TestCallToolProto_ADiscoveryToolWithNoDiscoveryResultIsCounted(t *testing.T) {
	// A real catalog tool, so componentcatalog says it emits a DiscoveryResult.
	const tool = "nmap"
	require.True(t, NewToolValidator(slog.Default()).isDiscoveryTool(tool),
		"this test needs a tool the catalog calls a discovery tool")

	before := testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "missing_discovery_field", "run-625"))
	beforeCompliance := testutil.ToFloat64(toolDiscoveryComplianceTotal.WithLabelValues(tool, "false", "run-625"))

	dispatchToolCall(t, tool, "testtool", createTestFileDescriptorSetForCallback(), setResult)

	assert.InDelta(t, before+1,
		testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "missing_discovery_field", "run-625")), 0.5,
		"the skip metric did not move; the validator is not on the dispatch path")
	assert.InDelta(t, beforeCompliance+1,
		testutil.ToFloat64(toolDiscoveryComplianceTotal.WithLabelValues(tool, "false", "run-625")), 0.5,
		"the compliance metric did not record a non-compliant dispatch")
}

// And a discovery tool that DID emit one is recorded compliant. Without this,
// the test above would pass on a validator that marked everything
// non-compliant.
func TestCallToolProto_ADiscoveryToolWithADiscoveryResultIsCompliant(t *testing.T) {
	const tool = "httpx"
	require.True(t, NewToolValidator(slog.Default()).isDiscoveryTool(tool))

	before := testutil.ToFloat64(toolDiscoveryComplianceTotal.WithLabelValues(tool, "true", "run-625"))

	dispatchToolCall(t, tool, "testdisc", discoveryShapedFDS(t), func(response proto.Message) {
		setResult(response)
		refl := response.ProtoReflect()
		field := refl.Descriptor().Fields().ByNumber(100)
		require.NotNil(t, field, "the output type has no field 100")

		// One host, set through the dynamic message. ExtractDiscovery marshals
		// field 100 and unmarshals the bytes into the real DiscoveryResult, so
		// the field numbers are what make this work.
		disc := refl.NewField(field).Message()
		hosts := disc.Descriptor().Fields().ByName("hosts")
		host := disc.NewField(hosts).List().NewElement().Message()
		host.Set(host.Descriptor().Fields().ByName("ip"), protoreflect.ValueOfString("10.60.0.103"))
		list := disc.Mutable(hosts).List()
		list.Append(protoreflect.ValueOfMessage(host))
		refl.Set(field, protoreflect.ValueOfMessage(disc))
	})

	assert.InDelta(t, before+1,
		testutil.ToFloat64(toolDiscoveryComplianceTotal.WithLabelValues(tool, "true", "run-625")), 0.5,
		"a compliant dispatch was not recorded")
}

// A tool the catalog does not call a discovery tool is compliant by definition
// and must NOT be counted as a missing DiscoveryResult. Otherwise every
// non-discovery tool call would look like a broken parser.
func TestCallToolProto_ANonDiscoveryToolIsNotCountedAsMissing(t *testing.T) {
	const tool = "not-in-the-catalog"
	require.False(t, NewToolValidator(slog.Default()).isDiscoveryTool(tool))

	before := testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "missing_discovery_field", "run-625"))
	beforeNotOne := testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "not_discovery_tool", "run-625"))

	dispatchToolCall(t, tool, "testtool", createTestFileDescriptorSetForCallback(), setResult)

	assert.InDelta(t, before,
		testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "missing_discovery_field", "run-625")), 0.5,
		"a non-discovery tool was counted as missing a DiscoveryResult")
	// It is still RECORDED, under its own reason, so the metric distinguishes
	// "this tool does not produce graph nodes" from "it should have and did not".
	assert.InDelta(t, beforeNotOne+1,
		testutil.ToFloat64(toolExtractionSkippedTotal.WithLabelValues(tool, "not_discovery_tool", "run-625")), 0.5,
		"the dispatch was not recorded at all")
}

// discoveryShapedFDS is a FileDescriptorSet whose output type declares field 100
// as a DiscoveryResult, wire-compatible with gibson.graphrag.v1.DiscoveryResult.
//
// The shared createTestFileDescriptorSetForCallback declares field 100 as a
// google.protobuf.Any "for simplicity", and that makes extraction impossible:
// ExtractDiscovery marshals the field and unmarshals the bytes as a
// DiscoveryResult, so an Any's type_url+value bytes come back as "cannot parse
// invalid wire-format data". The pre-existing extraction test packed an Any and
// only LOGGED whether the field survived, which is why nothing noticed.
//
// Only the fields this test sets are declared, at the real numbers
// (DiscoveryResult.hosts = 1, Host.ip = 2), which is all wire compatibility
// needs.
func discoveryShapedFDS(t *testing.T) string {
	t.Helper()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("testdisc.proto"),
		Package: proto.String("testdisc"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("ToolInput"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name:   proto.String("query"),
					Number: proto.Int32(1),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				}},
			},
			{
				Name: proto.String("ToolOutput"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:   proto.String("result"),
						Number: proto.Int32(1),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:   proto.String("count"),
						Number: proto.Int32(2),
						Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
						Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
					{
						Name:     proto.String("discovery_result"),
						Number:   proto.Int32(100),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: proto.String(".testdisc.DiscoveryResult"),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					},
				},
			},
			{
				Name: proto.String("DiscoveryResult"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name:     proto.String("hosts"),
					Number:   proto.Int32(1),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: proto.String(".testdisc.Host"),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
				}},
			},
			{
				Name: proto.String("Host"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name:   proto.String("ip"),
					Number: proto.Int32(2),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				}},
			},
		},
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{file},
	})
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}
