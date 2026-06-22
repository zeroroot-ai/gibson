package harness

import (
	"context"
	"testing"
)

// stubProvider is a deterministic MetadataProvider for tests.
type stubProvider struct {
	precedence int
	tags       TagSet
}

func (s stubProvider) Precedence() int { return s.precedence }
func (s stubProvider) Provide(ctx context.Context, m HarnessMethod, r any) TagSet {
	return s.tags
}

func TestTagMerger_PrecedenceOrder_1_2_5(t *testing.T) {
	// Only precedences 1, 2, and 5 are wired in this spec. Verify that
	// higher precedence wins on collision. Uses valid reserved-key
	// vocabulary values so the validator doesn't drop them.
	merger := NewTagMerger(nil, nil)
	merger.SetDaemonDefaults(TagSet{
		ResourceTags: map[string]string{"env": "dev", "gibson_version": "1.0"},
	})

	target := TagSet{
		ResourceTags: map[string]string{"env": "prod", "owner": "sec"},
	}
	mission := TagSet{
		ResourceTags: map[string]string{"env": "staging", "project": "apollo"},
	}

	rt, _ := merger.Merge(context.Background(), MethodCallToolProto, nil, target, mission)

	// Target (precedence 1) wins the env collision.
	if rt["env"] != "prod" {
		t.Errorf("env = %q; want prod (target wins)", rt["env"])
	}
	// Mission (precedence 2) wins over defaults.
	if rt["project"] != "apollo" {
		t.Errorf("project = %q; want apollo", rt["project"])
	}
	// Defaults still contribute non-colliding keys.
	if rt["gibson_version"] != "1.0" {
		t.Errorf("gibson_version = %q; want 1.0", rt["gibson_version"])
	}
	// Target contributes non-colliding keys.
	if rt["owner"] != "sec" {
		t.Errorf("owner = %q; want sec", rt["owner"])
	}
}

func TestTagMerger_ProviderPlugInHooks(t *testing.T) {
	// Verify that plug-in providers at precedence 3 and 4 slot in between
	// mission (2) and defaults (5). Uses a non-reserved key ("team") for
	// the collision case so the reserved-key validator doesn't interfere.
	merger := NewTagMerger(nil, nil)
	merger.RegisterProvider(stubProvider{
		precedence: PrecedenceAgent,
		tags:       TagSet{ResourceTags: map[string]string{"agent_tag": "from_agent", "team": "from_agent"}},
	})
	merger.RegisterProvider(stubProvider{
		precedence: PrecedenceToolPlugin,
		tags:       TagSet{ResourceTags: map[string]string{"tool_tag": "from_tool", "team": "from_tool"}},
	})
	merger.SetDaemonDefaults(TagSet{
		ResourceTags: map[string]string{"team": "from_default"},
	})

	rt, _ := merger.Merge(
		context.Background(),
		MethodCallToolProto,
		nil,
		TagSet{ResourceTags: map[string]string{"team": "from_target"}},
		TagSet{ResourceTags: map[string]string{"team": "from_mission"}},
	)

	// Target wins (highest precedence).
	if rt["team"] != "from_target" {
		t.Errorf("team = %q; want from_target", rt["team"])
	}
	// Plug-in providers contribute their unique keys.
	if rt["agent_tag"] != "from_agent" {
		t.Errorf("agent_tag missing: %v", rt)
	}
	if rt["tool_tag"] != "from_tool" {
		t.Errorf("tool_tag missing: %v", rt)
	}
}

func TestTagMerger_ReservedKeyCollisionLogging(t *testing.T) {
	// Collision on a reserved key must still merge correctly (higher
	// precedence wins) — the logging is a side effect we cannot easily
	// assert without a buffer logger, but we verify the value resolution.
	merger := NewTagMerger(nil, nil)
	rt, _ := merger.Merge(
		context.Background(),
		MethodCallToolProto,
		nil,
		TagSet{ResourceTags: map[string]string{"data_class": "pii"}},
		TagSet{ResourceTags: map[string]string{"data_class": "public"}},
	)
	if rt["data_class"] != "pii" {
		t.Errorf("data_class = %q; want pii", rt["data_class"])
	}
}

func TestTagMerger_CustomBag(t *testing.T) {
	// The custom bag is independent from resource_tags and follows the
	// same precedence rules.
	merger := NewTagMerger(nil, nil)
	_, custom := merger.Merge(
		context.Background(),
		MethodCallToolProto,
		nil,
		TagSet{Custom: map[string]string{"reason": "authorized"}},
		TagSet{Custom: map[string]string{"reason": "mission-default", "priority": "high"}},
	)
	if custom["reason"] != "authorized" {
		t.Errorf("reason = %q; want authorized (target wins)", custom["reason"])
	}
	if custom["priority"] != "high" {
		t.Errorf("priority = %q; want high", custom["priority"])
	}
}

func TestTagMerger_EmptyInputs(t *testing.T) {
	merger := NewTagMerger(nil, nil)
	rt, custom := merger.Merge(context.Background(), MethodComplete, nil, TagSet{}, TagSet{})
	if len(rt) != 0 || len(custom) != 0 {
		t.Errorf("empty inputs should produce empty outputs; got rt=%v custom=%v", rt, custom)
	}
}
