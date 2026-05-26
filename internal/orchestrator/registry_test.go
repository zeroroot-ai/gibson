package orchestrator

import (
	"context"
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func noopHandler(ctx context.Context, n *missionv1.MissionNode, p HandlerParams) (*ActionResult, error) {
	return &ActionResult{}, nil
}

func TestRegisterAndResolve(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()

	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, noopHandler)

	h, ok := ResolveNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT)
	if !ok {
		t.Fatal("AGENT handler not found after Register")
	}
	if h == nil {
		t.Fatal("AGENT handler is nil")
	}

	if _, ok := ResolveNodeHandler(missionv1.NodeType_NODE_TYPE_TOOL); ok {
		t.Error("TOOL should not resolve before registration")
	}
}

func TestRegisterDuplicate_panics(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()

	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, noopHandler)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
		s, _ := r.(string)
		if !strings.Contains(s, "already registered") {
			t.Errorf("panic message=%q want substring 'already registered'", s)
		}
	}()
	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, noopHandler)
}

func TestRegisterUnspecified_panics(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on UNSPECIFIED registration")
		}
	}()
	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_UNSPECIFIED, noopHandler)
}

func TestRegisterNil_panics(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on nil handler registration")
		}
	}()
	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, nil)
}

func TestAssertExhaustive_missing_panics(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()

	// Register only AGENT — the assertion should fail naming the
	// missing types.
	RegisterNodeHandler(missionv1.NodeType_NODE_TYPE_AGENT, noopHandler)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from AssertNodeRegistryExhaustive")
		}
		s, _ := r.(string)
		if !strings.Contains(s, "incomplete") {
			t.Errorf("panic=%q want substring 'incomplete'", s)
		}
	}()
	AssertNodeRegistryExhaustive()
}

func TestAssertExhaustive_complete(t *testing.T) {
	resetNodeRegistryForTesting()
	defer resetNodeRegistryForTesting()

	// Register every non-UNSPECIFIED enum value.
	for name, value := range missionv1.NodeType_value {
		if name == missionv1.NodeType_NODE_TYPE_UNSPECIFIED.String() {
			continue
		}
		RegisterNodeHandler(missionv1.NodeType(value), noopHandler)
	}

	// Should not panic.
	AssertNodeRegistryExhaustive()
}
