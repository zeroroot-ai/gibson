// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/zeroroot-ai/gibson/internal/engine/agentskill"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// sharedSkillPullTimeout bounds the pull of one Shared Agent Skill at start.
const sharedSkillPullTimeout = time.Minute

// sharedSkillPuller pulls one Shared Agent Skill. In production it is the
// operator Puller with the credential of the daemon process. A test supplies its
// own.
type sharedSkillPuller func(ctx context.Context, reference, name string) (*agentskill.Pulled, error)

// operatorSkillPuller builds the puller of the operator path. The operator config
// names the registry, so the address limit is off, and the daemon process
// credential is the one that the signature check also uses. This is the only
// place where that credential reaches an Agent Skill pull.
func operatorSkillPuller(credentialDir string, keychain func(string) authn.Keychain) sharedSkillPuller {
	puller := agentskill.NewPuller(agentskill.AllowPrivateAddresses())
	kc := keychain(credentialDir)
	return func(ctx context.Context, reference, name string) (*agentskill.Pulled, error) {
		ctx, cancel := context.WithTimeout(ctx, sharedSkillPullTimeout)
		defer cancel()
		return puller.Pull(ctx, reference, name, kc)
	}
}

// SharedAgentSkills is the operator source of Agent Skills. It holds what the
// daemon pulled at start. A reference that does not pull or does not validate is
// not offered, as for a component image that does not verify.
type SharedAgentSkills struct {
	entries map[string]api.SharedAgentSkill
}

var _ api.SharedAgentSkillSource = (*SharedAgentSkills)(nil)

// loadSharedAgentSkills pulls each configured reference. It returns the entries
// that passed and an error that names each one that did not. A caller offers the
// ones that passed.
func loadSharedAgentSkills(
	ctx context.Context, refs []config.SharedAgentSkillConfig, pull sharedSkillPuller, logger *slog.Logger,
) (*SharedAgentSkills, error) {
	out := &SharedAgentSkills{entries: make(map[string]api.SharedAgentSkill, len(refs))}
	var failed []string
	for _, r := range refs {
		if _, dup := out.entries[r.Name]; dup {
			failed = append(failed, r.Name+" (listed twice)")
			continue
		}
		p, err := pull(ctx, r.Reference, r.Name)
		if err != nil {
			logger.Error("shared Agent Skill not offered", "name", r.Name, "error", err)
			failed = append(failed, r.Name)
			continue
		}
		out.entries[r.Name] = api.SharedAgentSkill{Reference: r.Reference, Pulled: p}
	}
	if len(failed) > 0 {
		return out, fmt.Errorf("daemon: %d shared Agent Skill(s) not offered: %s", len(failed), strings.Join(failed, ", "))
	}
	return out, nil
}

// Names returns the offered names in order.
func (s *SharedAgentSkills) Names() []string {
	names := make([]string, 0, len(s.entries))
	for n := range s.entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Get returns the entry of a name.
func (s *SharedAgentSkills) Get(name string) (api.SharedAgentSkill, bool) {
	e, ok := s.entries[name]
	return e, ok
}

// agentSkillGate is the part of the authorizer that the platform gate needs.
type agentSkillGate interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
	ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error)
}

// seedSharedAgentSkillGate converges the platform gate of the Shared Agent
// Skills, as seedComponentCatalogGate does for connectors: each offered name gets
// a platform_enabled tuple from the system tenant on its shared object, and the
// tuple of a name that left the config is removed. It is a startup converge.
func seedSharedAgentSkillGate(
	ctx context.Context, fga agentSkillGate, shared *SharedAgentSkills, logger *slog.Logger,
) error {
	want := map[string]bool{}
	for _, name := range shared.Names() {
		obj, err := authz.SharedAgentSkillObject(name)
		if err != nil {
			return fmt.Errorf("daemon: shared Agent Skill gate: %w", err)
		}
		want[obj] = true
	}
	existing, err := fga.ListObjects(ctx, "system_tenant:_system", "platform_enabled", "agent_skill")
	if err != nil {
		return fmt.Errorf("daemon: shared Agent Skill gate: list platform_enabled: %w", err)
	}
	have := map[string]bool{}
	var retired []authz.Tuple
	for _, e := range existing {
		obj := e
		if !strings.HasPrefix(obj, "agent_skill:") {
			obj = "agent_skill:" + obj
		}
		have[obj] = true
		if !strings.HasPrefix(obj, "agent_skill:"+authz.SharedAgentSkillTenant+authz.TenantQualifiedSep) {
			continue
		}
		if !want[obj] {
			retired = append(retired, authz.Tuple{User: "system_tenant:_system", Relation: "platform_enabled", Object: obj})
		}
	}
	var add []authz.Tuple
	for obj := range want {
		if !have[obj] {
			add = append(add, authz.Tuple{User: "system_tenant:_system", Relation: "platform_enabled", Object: obj})
		}
	}
	if len(add) > 0 {
		if err := fga.Write(ctx, add); err != nil {
			return fmt.Errorf("daemon: shared Agent Skill gate: write %d tuples: %w", len(add), err)
		}
	}
	if len(retired) > 0 {
		if err := fga.Delete(ctx, retired); err != nil {
			return fmt.Errorf("daemon: shared Agent Skill gate: delete %d tuples: %w", len(retired), err)
		}
	}
	logger.Info("shared Agent Skill gate converged", "written", len(add), "deleted", len(retired))
	return nil
}

// seedSharedAgentSkillGateUntilDone runs seedSharedAgentSkillGate until it
// succeeds or ctx ends. A failed seed waits delay(n) before retry n (n starts
// at 1). Without the retry, an OpenFGA that is not ready at start leaves the
// gate closed, and each enable of a Shared Agent Skill returns NotFound until
// the daemon restarts.
func seedSharedAgentSkillGateUntilDone(
	ctx context.Context, fga agentSkillGate, shared *SharedAgentSkills, logger *slog.Logger,
	delay func(retry int) time.Duration,
) {
	for retry := 1; ; retry++ {
		err := seedSharedAgentSkillGate(ctx, fga, shared, logger)
		if err == nil {
			return
		}
		wait := delay(retry)
		logger.Warn("shared Agent Skill gate seed failed, will retry", "error", err, "retry", retry, "retry_in", wait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			logger.Warn("shared Agent Skill gate seed stopped before it succeeded", "error", ctx.Err())
			return
		case <-timer.C:
		}
	}
}
