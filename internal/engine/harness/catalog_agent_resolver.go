// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// defaultCatalogAgentSandboxClass is the setec SandboxClass a catalog agent
// launches under when the deployment config names none (ADR-0016 decision 4 —
// gibson must name the isolation posture, never inherit the cluster default,
// ADR-0052). It matches config.DefaultAgentSandboxClass; the resolver keeps its
// own copy so the harness does not import the daemon config package.
const defaultCatalogAgentSandboxClass = "agent"

// CatalogAgentResolver is the production AgentLaunchSpecResolver.
var _ AgentLaunchSpecResolver = (*CatalogAgentResolver)(nil)

// ErrAgentNotInCatalog is returned when an agent name has no signed catalog
// manifest. A sandboxed dispatch has no launch spec then, so the harness denies
// it fail-closed rather than launching an unknown image (ADR-0016).
var ErrAgentNotInCatalog = errors.New("agent not in component catalog")

// agentCatalogLookup is the catalog surface the resolver needs: find the
// agent-kind entry for a catalog id. componentcatalog.LookupAgent satisfies it;
// a test supplies a stub so the resolver is exercised without shipping an agent
// manifest into the embedded catalog.
type agentCatalogLookup func(id string) (componentcatalog.AgentEntry, bool)

// CredentialSource resolves one credential field of a tenant's own provider
// configuration, by provider type. The daemon backs it with the per-tenant
// provider store; tests fake it. A missing provider or key is an error, so a
// manifest that needs a credential is never launched with an empty one.
type CredentialSource interface {
	ResolveProviderCredential(ctx context.Context, tenant, provider, key string) (string, error)
}

// ErrTenantCredentialMissing wraps a credential the dispatching tenant has
// not configured for a provider the manifest requires.
var ErrTenantCredentialMissing = errors.New("tenant provider credential missing")

// ErrUnknownLoginShape is returned when a launch names a login shape the
// platform does not have (ADR-0019 decision 4).
var ErrUnknownLoginShape = errors.New("unknown login shape")

// ErrUnknownInstanceMode is returned when a launch names an instance mode the
// platform does not have.
var ErrUnknownInstanceMode = errors.New("unknown instance mode")

// ErrNoMemberCommand is returned when a launch asks for member mode from an
// agent whose manifest declares no member command. Such an agent has no
// long-lived driver, so a refusal is the true answer rather than a launch that
// would run the one-shot process and exit at once.
var ErrNoMemberCommand = errors.New("agent has no member command")

// ErrSubscriptionShapeCredential is returned when a manifest would inject a
// model credential under the subscription shape, which must inject none.
var ErrSubscriptionShapeCredential = errors.New("the subscription shape must set no model credential")

// ErrModelBelowFloor is returned when the model a dispatch would run under has
// a smaller context window than the agent's manifest requires. The dispatch is
// refused rather than launched: a model under the floor does not fail, it
// truncates, and a truncated answer is returned as a successful run
// (gibson#1692).
var ErrModelBelowFloor = errors.New("resolved model is below the agent's minimum context window")

// TenantModelResolver resolves the model a dispatched agent will run under for
// one tenant, and reports that model's context window so a manifest floor can
// be enforced before launch.
//
// The daemon backs it with the same per-tenant slot resolution a mission uses,
// so a dispatched agent and a mission agree on what the tenant's model is;
// tests fake it. It is consulted only when a manifest declares a floor, so an
// agent without one keeps dispatching with no model resolution at all.
type TenantModelResolver interface {
	// ResolveAgentModel returns the model name and its context window. pinned is
	// the manifest's model, or "" when the manifest pins none and the tenant
	// default applies. minContextWindow is the manifest floor, always > 0 here.
	//
	// An implementation that cannot satisfy the floor must return an error
	// rather than its best effort: returning a smaller model would put the
	// choice back in the caller's hands, and the caller cannot see the
	// truncation it causes.
	ResolveAgentModel(ctx context.Context, tenant, pinned string, minContextWindow int) (model string, contextWindow int, err error)
}

// CatalogAgentResolver resolves a sandboxed agent's launch spec from the signed
// component-catalog manifest (ADR-0015 / ADR-0016). It is the production
// AgentLaunchSpecResolver the daemon wires (gibson#1597): given an agent name it
// reads that agent's manifest and returns the image, sandbox class, egress
// ceiling and model the ephemeral launcher runs the agent under. An agent with
// no manifest is a clear error, so the harness denies the dispatch fail-closed.
type CatalogAgentResolver struct {
	lookup       agentCatalogLookup
	sandboxClass string
	credentials  CredentialSource
	models       TenantModelResolver
}

// NewCatalogAgentResolver builds the catalog-backed resolver. sandboxClass is
// the deployment-default setec SandboxClass an agent launches under when its
// manifest names none (config.SandboxSetecConfig.AgentSandboxClass); an empty
// value defaults to "agent" so a launch never inherits the cluster-default
// isolation posture (ADR-0052).
func NewCatalogAgentResolver(sandboxClass string, credentials CredentialSource) *CatalogAgentResolver {
	if sandboxClass == "" {
		sandboxClass = defaultCatalogAgentSandboxClass
	}
	return &CatalogAgentResolver{
		lookup:       componentcatalog.LookupAgent,
		sandboxClass: sandboxClass,
		credentials:  credentials,
	}
}

// WithTenantModelResolver supplies the per-tenant model resolution a manifest
// context-window floor is checked against (gibson#1692). It is optional: an
// agent whose manifest declares no floor never consults it. Without it, an
// agent that DOES declare a floor is refused at resolve time rather than
// launched unchecked, because an unverifiable floor and a satisfied one must
// not look the same.
func (r *CatalogAgentResolver) WithTenantModelResolver(m TenantModelResolver) *CatalogAgentResolver {
	r.models = m
	return r
}

// ResolveAgentLaunchSpec returns the sandboxed launch spec for the named agent,
// sourced from its signed catalog manifest. The image is the manifest's
// digest-pinned image, the sandbox class is the configured agent class, the
// egress is built from the manifest's egressAllow ceiling, and the model is the
// manifest's model. An agent with no manifest returns ErrAgentNotInCatalog so
// the harness denies the dispatch fail-closed.
//
// The tenant is not used yet: this slice takes the model from the manifest.
// ADR-0016 decision 7 resolves the newest tenant model at dispatch in a later
// slice, which is why the interface already carries the tenant.
func (r *CatalogAgentResolver) ResolveAgentLaunchSpec(ctx context.Context, req AgentLaunchRequest) (sandboxed.AgentLaunchSpec, error) {
	agentName := req.AgentName
	// The tenant is the caller's, from the context, never from the request
	// (Requirement 8.7). It selects which tenant's provider credentials the
	// sandbox is launched with, so it must not be nameable by the caller.
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return sandboxed.AgentLaunchSpec{}, fmt.Errorf("%q: no tenant in context; refusing to resolve a launch spec", agentName)
	}
	if !IsInstanceMode(req.Mode) {
		return sandboxed.AgentLaunchSpec{}, fmt.Errorf("%q: instance mode %q is not %s or %s: %w",
			agentName, req.Mode, ModeOneShot, ModeMember, ErrUnknownInstanceMode)
	}
	shape := req.LoginShape
	if shape == "" {
		shape = componentcatalog.LoginShapeAPIKey
	}
	if !componentcatalog.IsLoginShape(shape) {
		return sandboxed.AgentLaunchSpec{}, fmt.Errorf("%q: login shape %q is not one of %s: %w",
			agentName, shape, strings.Join(componentcatalog.LoginShapes(), ", "), ErrUnknownLoginShape)
	}
	entry, ok := r.lookup(agentName)
	if !ok {
		return sandboxed.AgentLaunchSpec{}, fmt.Errorf("%q: %w", agentName, ErrAgentNotInCatalog)
	}
	command, cmdErr := launchCommand(agentName, req.Mode, entry)
	if cmdErr != nil {
		return sandboxed.AgentLaunchSpec{}, cmdErr
	}
	spec := sandboxed.AgentLaunchSpec{
		Image:        entry.Image,
		Command:      command,
		Mode:         req.Mode,
		VCPU:         agentVCPUOrDefault(entry.Resources.VCPU),
		Memory:       agentMemoryOrDefault(entry.Resources.Memory),
		SandboxClass: r.sandboxClass,
		Egress:       sandboxed.EgressRulesFromAllow(entry.EgressAllow),
		Model:        entry.Model,
	}
	// A manifest floor is checked against the model this dispatch would really
	// run under, for THIS tenant, before anything launches (gibson#1692).
	if entry.MinContextWindow > 0 {
		model, err := r.resolveModelMeetingFloor(ctx, tenant, agentName, entry)
		if err != nil {
			return sandboxed.AgentLaunchSpec{}, err
		}
		spec.Model = model
	}
	// The manifest names the tenant credentials the sandbox needs. They come
	// from the DISPATCHING tenant's own provider configuration (ADR-0019
	// decision 4): the tenant pays, and no platform key enters a tenant
	// sandbox. A tenant without the provider is refused here, before launch.
	env, err := r.resolveShapeEnv(ctx, tenant, agentName, shape, entry.Credentials)
	if err != nil {
		return sandboxed.AgentLaunchSpec{}, err
	}
	if len(env) > 0 {
		spec.Env = env
	}
	return spec, nil
}

// resolveShapeEnv builds the credential environment for one login shape.
//
// A block with no shape is injected whatever the shape: it is a credential the
// agent needs to do its job, not one that reaches a model. A block with a shape
// is injected only for that shape, so one manifest carries every route and a
// launch takes exactly one.
//
// The subscription shape has no block of its own — the person signs in inside
// the sandbox, through the vendor's own flow, and the platform stores nothing.
// It therefore injects no model credential, and this function refuses to let
// one through by another door: an unshaped block naming an Anthropic key or a
// route flag is an error, not a silent override. In `-p` mode an API key beats
// the OAuth login, so such a manifest would send the person's sign-in bill to
// the tenant's key and nobody would see it happen.
func (r *CatalogAgentResolver) resolveShapeEnv(
	ctx context.Context, tenant, agentName, shape string, reqs []componentcatalog.CredentialRequirement,
) (map[string]string, error) {
	env := map[string]string{}
	for k, v := range componentcatalog.LoginShapeFlags(shape) {
		env[k] = v
	}
	for _, req := range reqs {
		if req.Shape != "" && req.Shape != shape {
			continue
		}
		if shape == componentcatalog.LoginShapeSubscription {
			if err := refuseModelCredential(agentName, req); err != nil {
				return nil, err
			}
		}
		if r.credentials == nil {
			return nil, fmt.Errorf("%q needs tenant credentials but no credential source is wired", agentName)
		}
		for _, field := range req.Fields() {
			value, err := r.credentials.ResolveProviderCredential(ctx, tenant, req.Provider, field.Key)
			if err != nil {
				if field.Optional && errors.Is(err, ErrTenantCredentialMissing) {
					continue
				}
				return nil, fmt.Errorf("%q needs the tenant's %s credential (%s): %w",
					agentName, req.Provider, field.Key, err)
			}
			if value == "" {
				if field.Optional {
					continue
				}
				return nil, fmt.Errorf("%q needs the tenant's %s credential (%s): %w",
					agentName, req.Provider, field.Key, ErrTenantCredentialMissing)
			}
			env[field.Env] = value
		}
	}
	return env, nil
}

// modelCredentialEnvs are the variables that would put a model credential in
// front of a person's own sign-in. They may never be set under the
// subscription shape.
var modelCredentialEnvs = map[string]bool{
	"ANTHROPIC_API_KEY":    true,
	"ANTHROPIC_AUTH_TOKEN": true,
}

func refuseModelCredential(agentName string, req componentcatalog.CredentialRequirement) error {
	for _, field := range req.Fields() {
		if modelCredentialEnvs[field.Env] || strings.HasPrefix(field.Env, "CLAUDE_CODE_USE_") {
			return fmt.Errorf(
				"%q declares %s for every login shape, but the %s shape must set no model credential (an API key beats the person's own sign-in): %w",
				agentName, field.Env, componentcatalog.LoginShapeSubscription, ErrSubscriptionShapeCredential)
		}
	}
	return nil
}

// launchCommand picks the command for the mode. One image carries both shapes,
// so the mode selects the entry point rather than the image.
func launchCommand(agentName, mode string, entry componentcatalog.AgentEntry) ([]string, error) {
	if mode != ModeMember {
		return entry.Command, nil
	}
	if len(entry.MemberCommand) == 0 {
		return nil, fmt.Errorf("%q declares no memberCommand, so it cannot join a bank: %w",
			agentName, ErrNoMemberCommand)
	}
	return entry.MemberCommand, nil
}

// Default sandbox size for a catalog agent. An agent runs a coding model
// with tools, so it is sized like a devbox, above a tool launch; the sandbox
// class caps it (the "agent" class allows 4 vCPU / 8Gi). setec's Sandbox CRD
// refuses vcpu < 1, so an unsized manifest must never reach it as zero.
const (
	DefaultAgentVCPU   int32  = 2
	DefaultAgentMemory string = "4Gi"
)

func agentVCPUOrDefault(v int32) int32 {
	if v > 0 {
		return v
	}
	return DefaultAgentVCPU
}

func agentMemoryOrDefault(m string) string {
	if m != "" {
		return m
	}
	return DefaultAgentMemory
}

// resolveModelMeetingFloor resolves the tenant's model for an agent that
// declares a minimum context window, and refuses the dispatch unless that model
// actually clears the floor.
//
// Both refusals below are deliberate. With no resolver wired the floor cannot
// be checked at all, and launching anyway would report success over a
// truncation nobody can see. And a resolver that answers with a model under the
// floor is re-checked here rather than trusted: the floor is the manifest's
// claim about what the agent needs, so the last word belongs on this side of
// the seam.
func (r *CatalogAgentResolver) resolveModelMeetingFloor(
	ctx context.Context, tenant, agentName string, entry componentcatalog.AgentEntry,
) (string, error) {
	if r.models == nil {
		return "", fmt.Errorf(
			"%q requires a model with at least %d tokens of context but no tenant model resolver is wired, so the floor cannot be checked: %w",
			agentName, entry.MinContextWindow, ErrModelBelowFloor)
	}
	model, window, err := r.models.ResolveAgentModel(ctx, tenant, entry.Model, entry.MinContextWindow)
	if err != nil {
		return "", fmt.Errorf(
			"%q requires a model with at least %d tokens of context: %w",
			agentName, entry.MinContextWindow, err)
	}
	if window < entry.MinContextWindow {
		return "", fmt.Errorf(
			"%q requires a model with at least %d tokens of context, but %q for tenant %q has %d: %w",
			agentName, entry.MinContextWindow, model, tenant, window, ErrModelBelowFloor)
	}
	return model, nil
}
