// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package auditcel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/celenv"
)

var sampleEvent = Event{
	Action:       "grant_created",
	ResourceType: "agent_grant",
	ResourceID:   "agent_principal:abc",
	Effect:       "allow",
	ActorID:      "user-1",
	ActorType:    "user",
	Time:         time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
}

func TestRule_Matches(t *testing.T) {
	cases := map[string]bool{
		`event.action == "grant_created"`:                                                true,
		`event.action == "grant_created" && event.effect == "allow"`:                     true,
		`event.resource_type == "agent_grant" && event.resource_id.startsWith("agent_")`: true,
		`event.actor_type == "user" && event.actor_id == "user-1"`:                       true,
		`event.time > timestamp("2026-01-01T00:00:00Z")`:                                 true,
		`event.action in ["agent_registered", "agent_revoked"]`:                          false,
		`event.effect == "deny"`:                                                         false,
	}
	for expr, want := range cases {
		t.Run(expr, func(t *testing.T) {
			r, err := Compile(expr)
			require.NoError(t, err)
			got, err := r.Match(context.Background(), sampleEvent)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestRule_FailsToCompile(t *testing.T) {
	cases := map[string]string{
		"empty":               "  ",
		"syntax":              `event.action ==`,
		"undeclared field":    `event.tenant_id == "acme"`,
		"undeclared variable": `action == "x"`,
		"undeclared function": `evidenceText(event) == ""`,
		"proof variable":      `evidence.exists(e, true)`,
		"not bool":            `event.action`,
	}
	for name, expr := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(expr)
			require.Error(t, err)
		})
	}
}

// TestProofPredicateCannotReadTheAuditEvent: the proof environment does not
// declare "event", so a proof predicate cannot read an audit event.
func TestProofPredicateCannotReadTheAuditEvent(t *testing.T) {
	_, err := celenv.Compile(`event.action == "grant_created"`)
	require.ErrorContains(t, err, "undeclared reference")
}

func TestMatch_CancelledContext(t *testing.T) {
	r, err := Compile(`true`)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = r.Match(ctx, sampleEvent)
	require.Error(t, err)
}

func TestLoadMappingRules(t *testing.T) {
	t.Run("nil pack", func(t *testing.T) {
		_, err := LoadMappingRules(nil)
		require.ErrorIs(t, err, ErrNilDomainPack)
	})
	t.Run("no rule", func(t *testing.T) {
		got, err := LoadMappingRules(&ontology.DomainPack{Name: "p"})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("each rule compiles", func(t *testing.T) {
		got, err := LoadMappingRules(&ontology.DomainPack{Name: "p", MappingRules: []ontology.MappingRule{
			{ControlID: "ac-2", Expression: `event.action == "grant_created"`},
			{ControlID: "au-2", Expression: `event.effect == "deny"`},
		}})
		require.NoError(t, err)
		require.Len(t, got, 2)
		ok, err := got["ac-2"].Match(context.Background(), sampleEvent)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("one bad rule refuses the whole pack", func(t *testing.T) {
		got, err := LoadMappingRules(&ontology.DomainPack{Name: "p", MappingRules: []ontology.MappingRule{
			{ControlID: "ac-2", Expression: `event.action == "grant_created"`},
			{ControlID: "au-2", Expression: `evidence.size() > 0`},
		}})
		require.ErrorContains(t, err, `control "au-2"`)
		assert.Nil(t, got)
	})
	t.Run("a pack that fails Validate is refused", func(t *testing.T) {
		_, err := LoadMappingRules(&ontology.DomainPack{Name: "p", MappingRules: []ontology.MappingRule{
			{ControlID: "ac 2", Expression: `true`},
		}})
		require.Error(t, err)
	})
}
