package daemon

import (
	"strings"
	"testing"

	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/proto"
)

// TestProtovalidate_negativeMaxTokensPerCall covers the four
// `(buf.validate.field).int32 = { gte: 0 }` annotations added in
// mission-schema-canonicalization. Spec:
// mission-verb-noun-registry Requirement 10 AC 4.
func TestProtovalidate_negativeMaxTokensPerCall(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}

	cases := []struct {
		name string
		msg  proto.Message
	}{
		{
			name: "AgentNodeConfig negative",
			msg: &missionv1.AgentNodeConfig{
				AgentName:        "test",
				MaxTokensPerCall: ptrInt32(-1),
			},
		},
		{
			name: "ToolNodeConfig negative",
			msg: &missionv1.ToolNodeConfig{
				ToolName:         "test",
				MaxTokensPerCall: ptrInt32(-100),
			},
		},
		{
			name: "PluginNodeConfig negative",
			msg: &missionv1.PluginNodeConfig{
				PluginName:       "test",
				Method:           "do",
				MaxTokensPerCall: ptrInt32(-1),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.Validate(tc.msg); err == nil {
				t.Fatal("expected validation error for negative value, got nil")
			} else if !strings.Contains(err.Error(), "max_tokens_per_call") {
				t.Errorf("error=%q want substring 'max_tokens_per_call'", err.Error())
			}
		})
	}
}

func TestProtovalidate_zeroMaxTokensPerCall_passes(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}
	cases := []proto.Message{
		&missionv1.AgentNodeConfig{AgentName: "a", MaxTokensPerCall: ptrInt32(0)},
		&missionv1.ToolNodeConfig{ToolName: "t", MaxTokensPerCall: ptrInt32(0)},
		&missionv1.PluginNodeConfig{PluginName: "p", Method: "m", MaxTokensPerCall: ptrInt32(0)},
	}
	for _, msg := range cases {
		if err := v.Validate(msg); err != nil {
			t.Errorf("zero value should pass: %v on %T", err, msg)
		}
	}
}

func TestProtovalidate_unsetMaxTokensPerCall_passes(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}
	// Unset (optional) field: validation should not fire. Cascade
	// from mission-level cap kicks in at runtime, not validation.
	cases := []proto.Message{
		&missionv1.AgentNodeConfig{AgentName: "a"},
		&missionv1.ToolNodeConfig{ToolName: "t"},
		&missionv1.PluginNodeConfig{PluginName: "p", Method: "m"},
	}
	for _, msg := range cases {
		if err := v.Validate(msg); err != nil {
			t.Errorf("unset field should pass: %v on %T", err, msg)
		}
	}
}

// TestProtovalidate_emptyJoinWaitFor covers the
// `(buf.validate.field).repeated.min_items = 1` annotation on
// JoinNodeConfig.wait_for. Spec: mission-verb-noun-registry
// Requirement 10 AC 4 + Requirement 7 AC 5.
func TestProtovalidate_emptyJoinWaitFor(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}
	msg := &missionv1.JoinNodeConfig{} // empty wait_for
	if err := v.Validate(msg); err == nil {
		t.Fatal("expected validation error for empty wait_for, got nil")
	} else if !strings.Contains(err.Error(), "wait_for") {
		t.Errorf("error=%q want substring 'wait_for'", err.Error())
	}
}

func TestProtovalidate_nonEmptyJoinWaitFor_passes(t *testing.T) {
	v, err := buildProtovalidateValidator()
	if err != nil {
		t.Fatalf("buildProtovalidateValidator: %v", err)
	}
	msg := &missionv1.JoinNodeConfig{
		WaitFor:  []string{"upstream-1"},
		Strategy: missionv1.MergeStrategy_MERGE_STRATEGY_CONCAT,
	}
	if err := v.Validate(msg); err != nil {
		t.Errorf("non-empty wait_for should pass: %v", err)
	}
}

func ptrInt32(v int32) *int32 { return &v }
