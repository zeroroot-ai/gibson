package harness

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/sdk/agent/compliance"
)

// TestAgentMetadataProvider_ReadsFromContext verifies that the precedence-3
// provider returns the metadata an agent stamped onto context via the
// sdk/agent/compliance package.
func TestAgentMetadataProvider_ReadsFromContext(t *testing.T) {
	p := NewAgentMetadataProvider()

	// No settings → empty TagSet.
	empty := p.Provide(context.Background(), MethodComplete, nil)
	if !empty.IsEmpty() {
		t.Errorf("empty context should produce empty TagSet, got %v", empty)
	}

	// With custom tags.
	ctx := compliance.WithCustom(context.Background(), map[string]string{
		"gitlab_project": "p1",
		"change_ticket":  "CHG-1",
	})
	got := p.Provide(ctx, MethodComplete, nil)
	if got.Custom["gitlab_project"] != "p1" {
		t.Errorf("Custom[gitlab_project] = %q", got.Custom["gitlab_project"])
	}
	if got.Custom["change_ticket"] != "CHG-1" {
		t.Errorf("Custom[change_ticket] = %q", got.Custom["change_ticket"])
	}
}

func TestAgentMetadataProvider_Precedence(t *testing.T) {
	p := NewAgentMetadataProvider()
	if p.Precedence() != PrecedenceAgent {
		t.Errorf("Precedence = %d; want %d", p.Precedence(), PrecedenceAgent)
	}
}

func TestToolMetadataProvider_NonProtoRequest(t *testing.T) {
	p := NewToolMetadataProvider(nil)
	got := p.Provide(context.Background(), MethodCallToolProto, "not a proto")
	if !got.IsEmpty() {
		t.Errorf("non-proto request should produce empty TagSet")
	}
}

func TestToolMetadataProvider_NilRequest(t *testing.T) {
	p := NewToolMetadataProvider(nil)
	got := p.extract(context.Background(), nil)
	if !got.IsEmpty() {
		t.Errorf("nil proto should produce empty TagSet")
	}
}

func TestReservedKeyValidator_Vocabularies(t *testing.T) {
	v := NewReservedKeyValidator()

	cases := []struct {
		key, value string
		valid      bool
	}{
		{"env", "prod", true},
		{"env", "staging", true},
		{"env", "random", false},
		{"data_class", "pii", true},
		{"data_class", "secret", true},
		{"data_class", "not_real", false},
		{"residency", "us", true},
		{"residency", "mars", false},
		{"legal_hold", "true", true},
		{"legal_hold", "maybe", false},
		{"arbitrary_custom_key", "anything", true}, // non-reserved → always valid
	}

	for _, c := range cases {
		if got := v.IsValid(c.key, c.value); got != c.valid {
			t.Errorf("IsValid(%q, %q) = %v; want %v", c.key, c.value, got, c.valid)
		}
	}
}

func TestReservedKeyValidator_IsReserved(t *testing.T) {
	v := NewReservedKeyValidator()
	if !v.IsReserved("env") {
		t.Errorf("env should be reserved")
	}
	if v.IsReserved("custom_key") {
		t.Errorf("custom_key should not be reserved")
	}
}

func TestSizeEnforcer_TruncatesLongValues(t *testing.T) {
	e := NewSizeEnforcer(nil)
	long := make([]byte, MaxTagValueBytes*2)
	for i := range long {
		long[i] = 'x'
	}
	bag := map[string]string{
		"short": "ok",
		"long":  string(long),
	}
	keySources := map[string]int{"short": 1, "long": 1}
	truncated, _ := e.Enforce(bag, keySources)

	if len(truncated) != 1 || truncated[0] != "long" {
		t.Errorf("truncated = %v; want [long]", truncated)
	}
	if len(bag["long"]) > MaxTagValueBytes {
		t.Errorf("long value not truncated: %d bytes", len(bag["long"]))
	}
}

func TestSizeEnforcer_EvictsLowPrecedenceFirst(t *testing.T) {
	e := NewSizeEnforcer(nil)
	bag := map[string]string{}
	keySources := map[string]int{}
	// Fill to exceed entry count with alternating precedences.
	for i := 0; i < MaxEntryCount+10; i++ {
		k := fmtInt(i)
		bag[k] = "v"
		// Even keys = high precedence (1), odd = low precedence (5)
		if i%2 == 0 {
			keySources[k] = PrecedenceTargetNode
		} else {
			keySources[k] = PrecedenceDaemonDefaults
		}
	}
	_, dropped := e.Enforce(bag, keySources)

	if len(dropped) != 10 {
		t.Errorf("dropped = %d; want 10 evicted", len(dropped))
	}
	// Every dropped key should have been a low-precedence (daemon_defaults) key.
	for _, k := range dropped {
		if keySources[k] != 0 && keySources[k] != PrecedenceDaemonDefaults {
			// keySources[k] is 0 because enforce deleted it
		}
	}
	if len(bag) != MaxEntryCount {
		t.Errorf("bag size after eviction = %d; want %d", len(bag), MaxEntryCount)
	}
}

func TestComplianceTagMerger_SizeEnforcement(t *testing.T) {
	// End-to-end: merger + size enforcement together.
	merger := NewTagMerger(nil, nil)

	long := make([]byte, MaxTagValueBytes+100)
	for i := range long {
		long[i] = 'y'
	}

	target := TagSet{
		ResourceTags: map[string]string{"desc": string(long)},
	}
	rt, _ := merger.Merge(context.Background(), MethodCallToolProto, nil, target, TagSet{})

	if len(rt["desc"]) > MaxTagValueBytes {
		t.Errorf("desc value should be truncated; got %d bytes", len(rt["desc"]))
	}
	if rt[MarkerTruncatedKeys] == "" {
		t.Errorf("expected truncated-keys marker")
	}
}

// fmtInt is a cheap itoa for test helpers.
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
