// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
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
