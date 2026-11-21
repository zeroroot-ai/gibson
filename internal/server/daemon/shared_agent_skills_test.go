// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

func discardLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func okPuller(_ context.Context, _, name string) (*agentskill.Pulled, error) {
	if name == "broken" {
		return nil, errors.New("registry down")
	}
	return &agentskill.Pulled{Manifest: &agentskill.Manifest{Name: name, Description: "d"}, Digest: "sha256:" + name}, nil
}

// A reference that does not pull is not offered, and the others are.
func TestLoadSharedAgentSkills_SkipsWhatDoesNotPull(t *testing.T) {
	got, err := loadSharedAgentSkills(context.Background(), []config.SharedAgentSkillConfig{
		{Name: "web-recon", Reference: "r@sha256:a"},
		{Name: "broken", Reference: "r@sha256:b"},
		{Name: "web-recon", Reference: "r@sha256:c"},
	}, okPuller, discardLog())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
	assert.Contains(t, err.Error(), "web-recon (listed twice)")
	assert.Equal(t, []string{"web-recon"}, got.Names())
	e, ok := got.Get("web-recon")
	require.True(t, ok)
	assert.Equal(t, "r@sha256:a", e.Reference)
}

type gateFGA struct {
	existing []string
	written  []authz.Tuple
	deleted  []authz.Tuple
}

func (g *gateFGA) Check(context.Context, string, string, string) (bool, error) { return false, nil }
func (g *gateFGA) Write(_ context.Context, t []authz.Tuple) error {
	g.written = append(g.written, t...)
	return nil
}
func (g *gateFGA) Delete(_ context.Context, t []authz.Tuple) error {
	g.deleted = append(g.deleted, t...)
	return nil
}
func (g *gateFGA) ListObjects(context.Context, string, string, string) ([]string, error) {
	return g.existing, nil
}

// The gate converges: a new name gets its tuple, a name that left the config
// loses it, and a tuple of a tenant Agent Skill is never touched.
func TestSeedSharedAgentSkillGate_Converges(t *testing.T) {
	shared, _ := loadSharedAgentSkills(context.Background(), []config.SharedAgentSkillConfig{
		{Name: "web-recon", Reference: "r@sha256:a"}, {Name: "kept", Reference: "r@sha256:k"},
	}, okPuller, discardLog())
	fga := &gateFGA{existing: []string{
		"agent_skill:_shared/kept", "agent_skill:_shared/retired", "agent_skill:acme/own",
	}}
	require.NoError(t, seedSharedAgentSkillGate(context.Background(), fga, shared, discardLog()))
	assert.Equal(t, []authz.Tuple{
		{User: "system_tenant:_system", Relation: "platform_enabled", Object: "agent_skill:_shared/web-recon"},
	}, fga.written)
	assert.Equal(t, []authz.Tuple{
		{User: "system_tenant:_system", Relation: "platform_enabled", Object: "agent_skill:_shared/retired"},
	}, fga.deleted)
}

// storeGateFGA keeps tuples as a set. Its Check answers as the platform gate of
// EnableSharedAgentSkill does, so a test can seed the gate and then ask the
// question that the RPC asks.
type storeGateFGA struct{ tuples map[authz.Tuple]bool }

func newStoreGateFGA() *storeGateFGA { return &storeGateFGA{tuples: map[authz.Tuple]bool{}} }

func (s *storeGateFGA) Check(_ context.Context, user, relation, object string) (bool, error) {
	return s.tuples[authz.Tuple{User: user, Relation: relation, Object: object}], nil
}

func (s *storeGateFGA) Write(_ context.Context, t []authz.Tuple) error {
	for _, tp := range t {
		s.tuples[tp] = true
	}
	return nil
}

func (s *storeGateFGA) Delete(_ context.Context, t []authz.Tuple) error {
	for _, tp := range t {
		delete(s.tuples, tp)
	}
	return nil
}

func (s *storeGateFGA) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	var out []string
	for tp := range s.tuples {
		if tp.User == user && tp.Relation == relation && strings.HasPrefix(tp.Object, objectType+":") {
			out = append(out, tp.Object)
		}
	}
	return out, nil
}

func offered(t *testing.T, fga *storeGateFGA, name string) bool {
	t.Helper()
	obj, err := authz.SharedAgentSkillObject(name)
	require.NoError(t, err)
	ok, err := fga.Check(context.Background(), "system_tenant:_system", "platform_enabled", obj)
	require.NoError(t, err)
	return ok
}

// After the seed, the platform gate that EnableSharedAgentSkill checks is open
// for each configured name and for no other. A second seed changes nothing. A
// name that leaves the config closes the gate at the next seed.
func TestSeedSharedAgentSkillGate_OpensTheGateThatEnableChecks(t *testing.T) {
	ctx := context.Background()
	fga := newStoreGateFGA()
	load := func(names ...string) *SharedAgentSkills {
		var refs []config.SharedAgentSkillConfig
		for _, n := range names {
			refs = append(refs, config.SharedAgentSkillConfig{Name: n, Reference: "r@sha256:" + n})
		}
		s, err := loadSharedAgentSkills(ctx, refs, okPuller, discardLog())
		require.NoError(t, err)
		return s
	}

	require.NoError(t, seedSharedAgentSkillGate(ctx, fga, load("web-recon", "dns"), discardLog()))
	assert.True(t, offered(t, fga, "web-recon"))
	assert.True(t, offered(t, fga, "dns"))
	assert.False(t, offered(t, fga, "not-configured"))

	// A second seed with the same config is a no-op, and a new name joins the
	// ones that exist already.
	require.NoError(t, seedSharedAgentSkillGate(ctx, fga, load("web-recon", "dns"), discardLog()))
	require.NoError(t, seedSharedAgentSkillGate(ctx, fga, load("web-recon", "dns", "extra"), discardLog()))
	assert.Len(t, fga.tuples, 3)
	assert.True(t, offered(t, fga, "extra"))

	// A name that left the config loses its tuple. The others keep theirs.
	require.NoError(t, seedSharedAgentSkillGate(ctx, fga, load("web-recon"), discardLog()))
	assert.True(t, offered(t, fga, "web-recon"))
	assert.False(t, offered(t, fga, "dns"))
	assert.False(t, offered(t, fga, "extra"))
}
