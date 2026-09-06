// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package componentcatalog is the curated catalog of first-party components
// gibson ships, for ALL four kinds — agent, tool, plugin, connector (ADR-0015,
// generalizing the connector-only catalog of ADR-0014/0065). A component is one
// declarative manifest — no Go, no rebuild. The manifests are embedded into the
// gibson image; adding a first-party component is dropping in a manifest.
//
// A manifest is a common envelope (id, kind, displayName, description,
// egressAllow) plus a `spec` block whose shape is selected by `kind`. Each spec
// variant embeds that kind's existing runtime type, so the manifest cannot
// drift from what the runtime accepts.
//
// This is the "system_tenant / platform_enabled" public catalog: the daemon
// seeds a platform_enabled tuple per entry on its canonical
// `component:<kind>/<id>` object at startup (reconciler.SeedComponentCatalogGate).
// This table is the source of truth for what is listed; de-listing is removing
// the manifest here (ADR-0027: one loader, no per-kind parallel catalogs).
package componentcatalog

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// manifestFS holds the first-party component manifests, compiled into the
// gibson binary. Each file is one component.
//
//go:embed manifests/*.yaml
var manifestFS embed.FS

// Manifest is the common envelope every catalog entry shares. Exactly one of
// the kind-specific spec pointers is populated, selected by Kind after the
// `spec` node is decoded.
type Manifest struct {
	// ID is the stable catalog id. With Kind it forms the canonical FGA object
	// `component:<kind>/<id>`.
	ID string `yaml:"id"`
	// Kind is one of agent | tool | plugin | connector.
	Kind string `yaml:"kind"`
	// DisplayName is the human name for the catalog UI.
	DisplayName string `yaml:"displayName"`
	// Description is one sentence for the catalog UI.
	Description string `yaml:"description"`
	// EgressAllow is the egress ceiling for the component (ADR-0015). For an
	// agent it maps to the setec Launch.Egress of its tool dispatches; for a
	// workload it maps to the L7 profile + L3 NetworkPolicy.
	EgressAllow []string `yaml:"egressAllow"`
	// Spec is the kind-discriminated runtime block, decoded into exactly one of
	// the typed specs below.
	Spec yaml.Node `yaml:"spec"`

	connector *ConnectorSpec
	plugin    *PluginSpec
	tool      *ToolSpec
	agent     *AgentSpec
}

// ConnectorSpec embeds the ConnectorInstance-shaped fields (ADR-0014).
type ConnectorSpec struct {
	Vendor             string                               `yaml:"vendor"`
	Shape              connectorv1alpha1.ConnectorShape     `yaml:"shape"`
	Image              string                               `yaml:"image"`
	Endpoint           string                               `yaml:"endpoint"`
	Transport          connectorv1alpha1.ConnectorTransport `yaml:"transport"`
	Auth               connectorv1alpha1.ConnectorAuthKind  `yaml:"auth"`
	OAuthScope         string                               `yaml:"oauthScope"`
	DefaultInstanceURL string                               `yaml:"defaultInstanceUrl"`
}

// WorkloadSpec is the shared hosting shape for an external gRPC component
// workload (ADR-0015 decision 6, ADR-0066): a runtime, a digest-pinned image,
// and a SVID enrollment. Agents and plugins BOTH embed it — one workload code
// path (ADR-0027), because an agent is an external gRPC component hosted exactly
// like a plugin, not trusted in-image code.
type WorkloadSpec struct {
	Runtime string `yaml:"runtime"` // process | pod | setec
	Image   string `yaml:"image"`   // must be a signed digest (…@sha256:…)
	SVID    string `yaml:"svid"`
}

// PluginSpec is a plugin workload (ADR-0066): the shared workload hosting.
type PluginSpec struct {
	WorkloadSpec `yaml:",inline"`
}

// ToolSpec is the tool runtime block (ADR-0010/ADR-0017): content trust +
// dispatch mode, a digest-pinned image, the launch command, and the sandbox
// size. A manifest-seeded tool always carries a signed-digest image — the
// runtime `--list-tools` refresher is retired (ADR-0017), so the manifest is
// the only source of a tool's runtime shape.
type ToolSpec struct {
	ContentTrust string         `yaml:"contentTrust"` // trusted | untrusted
	DispatchMode string         `yaml:"dispatchMode"` // sandboxed | agent | plugin
	Command      string         `yaml:"command"`
	Image        string         `yaml:"image"` // required; must be a signed digest
	Resources    AgentResources `yaml:"resources"`
}

// AgentSpec is an agent workload: the SAME hosting as a plugin (ADR-0015
// decision 6 — agents are external gRPC components, not in-image), plus the
// agent's LLM/budget policy. It embeds WorkloadSpec so agent and plugin share
// one workload code path.
type AgentSpec struct {
	WorkloadSpec `yaml:",inline"`
	// DispatchMode declares how a catalog agent must be launched on dispatch.
	// "" is the default (route by the registry's content trust). "sandboxed"
	// forces the ephemeral setec sandbox launch regardless of registry trust,
	// because a platform agent is launched-on-dispatch, not a registered polling
	// worker, so its trust comes from this manifest, not the registry (ADR-0016).
	// It mirrors ToolSpec.DispatchMode.
	DispatchMode string `yaml:"dispatchMode"`
	// Command is the sandbox launch command (argv as one shell-split string).
	// Required when dispatchMode is sandboxed: setec refuses a launch with no
	// command and does not consult the image entrypoint.
	//
	// It is the ONE-SHOT command: the process that runs one dispatch and ends.
	Command string `yaml:"command"`
	// MemberCommand is the launch command for the member shape: a long-lived
	// process that serves many dispatches over its life (ADR-0019). One image
	// carries both shapes, so the difference is the command, not the image.
	//
	// An agent that declares none cannot run as a member, and a launch that
	// asks for member mode is refused. That is the honest answer for an agent
	// like zerocool, which has no member driver.
	MemberCommand string `yaml:"memberCommand"`
	// MaxJobsInFlight is how many jobs one instance of this agent can hold at
	// once. It is the agent's own answer to a question only the agent knows,
	// and a bank that names no cap takes it. Zero means one.
	MaxJobsInFlight int32 `yaml:"maxJobsInFlight"`
	// Resources sizes the sandbox. Optional: the resolver applies the agent
	// defaults (2 vCPU, 4Gi) when a field is zero; the sandbox class caps it.
	Resources   AgentResources `yaml:"resources"`
	Model       string         `yaml:"model"` // default slot-LLM policy
	BudgetLimit int            `yaml:"budgetLimit"`
	// MinContextWindow is the smallest context window, in tokens, a model must
	// have for this agent to do its job. Zero means the agent states no floor
	// and dispatches exactly as it always has.
	//
	// It exists because a REGISTERED agent could declare this itself, through
	// the SDK's LLM slot, but a dispatched one never registers: its model
	// arrives as GIBSON_MODEL, resolved against the tenant's own providers. So
	// the declaration has to live in the signed manifest or it does not exist.
	//
	// Under-provisioning is silent, which is the whole reason this is a field
	// rather than a comment: a model below the floor does not error, it
	// truncates, and the agent returns a short answer that reads as success.
	// The resolver therefore refuses the dispatch instead (gibson#1692).
	MinContextWindow int `yaml:"minContextWindow"`
	// Credentials the sandbox needs from the dispatching tenant's own provider
	// configuration (gibson#1621 decision 12). Each entry names a provider type
	// the tenant must have configured, and the env var the launch injects its
	// credential into. A tenant without that provider is refused at dispatch,
	// never launched with an empty key.
	Credentials []CredentialRequirement `yaml:"credentials"`
}

// DispatchModeSandboxed is the AgentSpec.DispatchMode value that forces a
// catalog agent to launch in an ephemeral setec sandbox on dispatch, whatever
// its registry content trust says (ADR-0016). An empty DispatchMode is the
// default and routes by registry trust.
const DispatchModeSandboxed = "sandboxed"

const digestMarker = "@sha256:"

// firstPartyRegistry is the image-name prefix of components gibson builds from
// source and cosign-signs in the release pipeline (reusable-image-build.yml,
// keyless OIDC + SLSA attestation). A first-party image MUST be pinned by digest
// so a tenant runs exactly the signed build; a third-party vendor image (any
// other registry, e.g. a hosted connector wrapping a vendor container) is a
// separate trust seam and is not held to this rule.
const firstPartyRegistry = "ghcr.io/zeroroot-ai/"

// requireFirstPartyImageDigest fails loud when a first-party image is not
// digest-pinned (ADR-0015 decision 9). Third-party images pass.
func requireFirstPartyImageDigest(id, image string) error {
	if strings.HasPrefix(image, firstPartyRegistry) && !strings.Contains(image, digestMarker) {
		return fmt.Errorf(
			"%s: a first-party image (%s…) must be built-from-source and digest-pinned (…%s…), got %q",
			id, firstPartyRegistry, digestMarker, image)
	}
	return nil
}

// validate checks the envelope and the kind-specific spec, decoding the spec
// into its typed form. A bad manifest fails the load loudly.
func (m *Manifest) validate() error {
	if m.ID == "" {
		return errors.New("id is required")
	}
	if !authz.IsComponentKind(m.Kind) {
		return fmt.Errorf("%s: kind %q must be one of agent, tool, plugin, connector", m.ID, m.Kind)
	}
	switch m.Kind {
	case authz.KindConnector:
		var s ConnectorSpec
		if err := m.Spec.Decode(&s); err != nil {
			return fmt.Errorf("%s: decode connector spec: %w", m.ID, err)
		}
		if err := validateConnector(m.ID, s); err != nil {
			return err
		}
		m.connector = &s
	case authz.KindPlugin:
		var s PluginSpec
		if err := m.Spec.Decode(&s); err != nil {
			return fmt.Errorf("%s: decode plugin spec: %w", m.ID, err)
		}
		if !strings.Contains(s.Image, digestMarker) {
			return fmt.Errorf("%s: a plugin image must be digest-pinned (…%s…), got %q", m.ID, digestMarker, s.Image)
		}
		m.plugin = &s
	case authz.KindTool:
		var s ToolSpec
		if err := m.Spec.Decode(&s); err != nil {
			return fmt.Errorf("%s: decode tool spec: %w", m.ID, err)
		}
		if !strings.Contains(s.Image, digestMarker) {
			return fmt.Errorf("%s: a tool image must be digest-pinned (…%s…), got %q", m.ID, digestMarker, s.Image)
		}
		m.tool = &s
	case authz.KindAgent:
		var s AgentSpec
		if err := m.Spec.Decode(&s); err != nil {
			return fmt.Errorf("%s: decode agent spec: %w", m.ID, err)
		}
		// An agent is an external gRPC component workload (ADR-0015 decision 6),
		// hosted like a plugin: its image must be digest-pinned.
		if !strings.Contains(s.Image, digestMarker) {
			return fmt.Errorf("%s: an agent image must be digest-pinned (…%s…), got %q", m.ID, digestMarker, s.Image)
		}
		if s.DispatchMode != "" && s.DispatchMode != DispatchModeSandboxed {
			return fmt.Errorf("%s: agent dispatchMode %q must be %q or empty", m.ID, s.DispatchMode, DispatchModeSandboxed)
		}
		// setec's Launch refuses "command must have at least one entry"; the
		// image entrypoint is not consulted. A sandboxed agent declares it.
		if s.DispatchMode == DispatchModeSandboxed && len(strings.Fields(s.Command)) == 0 {
			return fmt.Errorf("%s: a sandboxed agent must declare command (the sandbox launch command; setec refuses an empty one)", m.ID)
		}
		if err := validateCredentialRequirements(m.ID, s.Credentials); err != nil {
			return err
		}
		if s.MinContextWindow < 0 {
			return fmt.Errorf("%s: minContextWindow %d must not be negative", m.ID, s.MinContextWindow)
		}
		if s.MaxJobsInFlight < 0 {
			return fmt.Errorf("%s: maxJobsInFlight %d must not be negative", m.ID, s.MaxJobsInFlight)
		}
		// A member command only means anything on a sandboxed launch, which is
		// the only path that reads a command at all. Declaring one elsewhere
		// would ship a field that silently does nothing.
		if s.MemberCommand != "" && s.DispatchMode != DispatchModeSandboxed {
			return fmt.Errorf(
				"%s: memberCommand is used only on a %s dispatch, so declaring it with dispatchMode %q would do nothing",
				m.ID, DispatchModeSandboxed, s.DispatchMode)
		}
		// The floor is enforced where the model is resolved, which is the
		// sandboxed launch path. On any other dispatch mode nothing reads it, so
		// accepting it would ship a declaration that silently does nothing --
		// the same class of defect the field exists to close.
		if s.MinContextWindow > 0 && s.DispatchMode != DispatchModeSandboxed {
			return fmt.Errorf(
				"%s: minContextWindow is enforced only on a %s dispatch, so declaring it with dispatchMode %q would do nothing",
				m.ID, DispatchModeSandboxed, s.DispatchMode)
		}
		m.agent = &s
	}
	return nil
}

// AgentResources is the sandbox size a manifest asks for.
type AgentResources struct {
	VCPU   int32  `yaml:"vcpu"`
	Memory string `yaml:"memory"`
}

// CredentialRequirement is one block of tenant provider credentials the sandbox
// needs. A block names one provider and either one credential field (env + key)
// or several (envs), because a third-party inference route needs a whole set:
// Bedrock wants a key id, a secret, an optional session token and a region.
type CredentialRequirement struct {
	// Shape restricts the block to one login shape (ADR-0019 decision 4). Empty
	// means the block is injected whatever the shape — a credential the agent
	// needs to do its job rather than to reach a model. A named shape is
	// injected only when the launch asks for that shape, so one manifest
	// carries every route and a launch takes exactly one.
	Shape string `yaml:"shape"`
	// Provider is the provider type as the tenant configured it (e.g. "anthropic").
	Provider string `yaml:"provider"`
	// Env is the environment variable the launch injects the credential into.
	// Set it with Key for a single-field block; leave both empty and use Envs
	// for a multi-field one.
	Env string `yaml:"env"`
	// Key selects the credential field. Defaults to "api_key".
	Key string `yaml:"key"`
	// Envs is the multi-field form: each entry maps one credential field of the
	// provider to one environment variable. Exactly one of Env or Envs is set.
	Envs []CredentialEnv `yaml:"envs"`
	// Optional marks a block whose credential fields may be absent from the
	// tenant's provider record. A session token is only present on temporary
	// AWS credentials, so demanding it would refuse every launch on a static
	// key pair.
	Optional bool `yaml:"optional"`
}

// CredentialEnv maps one credential field of a provider to one environment
// variable in the sandbox.
type CredentialEnv struct {
	// Key is the credential field on the tenant's provider record.
	Key string `yaml:"key"`
	// Env is the environment variable the launch injects it into.
	Env string `yaml:"env"`
	// Optional marks a field that may be absent, like an AWS session token.
	Optional bool `yaml:"optional"`
}

// Fields returns the block as a flat list of (credential key, env var,
// optional) triples, so a caller reads the single-field and multi-field forms
// through one path.
func (r CredentialRequirement) Fields() []CredentialEnv {
	if len(r.Envs) > 0 {
		out := make([]CredentialEnv, len(r.Envs))
		copy(out, r.Envs)
		if r.Optional {
			for i := range out {
				out[i].Optional = true
			}
		}
		return out
	}
	return []CredentialEnv{{Key: r.Key, Env: r.Env, Optional: r.Optional}}
}

// envNamePattern is what a credential env var may look like: the launcher
// writes it straight into the sandbox environment.
var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func validateCredentialRequirements(id string, reqs []CredentialRequirement) error {
	// Env names are unique WITHIN a shape, not across the manifest. One launch
	// takes one shape, so Bedrock and Vertex blocks may both name AWS_REGION
	// without ever colliding at runtime; forbidding that would stop a manifest
	// from carrying every route, which is the whole point of the selector.
	seen := map[string]map[string]struct{}{}
	for i := range reqs {
		r := &reqs[i]
		if r.Provider == "" {
			return fmt.Errorf("%s: credentials[%d]: provider is required", id, i)
		}
		if r.Shape != "" && !IsLoginShape(r.Shape) {
			return fmt.Errorf("%s: credentials[%d]: shape %q is not a login shape (one of %s, or empty for every shape)",
				id, i, r.Shape, strings.Join(LoginShapes(), ", "))
		}
		if r.Shape == LoginShapeSubscription {
			return fmt.Errorf("%s: credentials[%d]: the %s shape stores no credential on the platform, so it cannot declare one",
				id, i, LoginShapeSubscription)
		}
		switch {
		case r.Env == "" && len(r.Envs) == 0:
			return fmt.Errorf("%s: credentials[%d]: declare either env or envs", id, i)
		case r.Env != "" && len(r.Envs) > 0:
			return fmt.Errorf("%s: credentials[%d]: declare either env or envs, not both", id, i)
		}
		if r.Env != "" && r.Key == "" {
			r.Key = "api_key"
		}
		for j := range r.Envs {
			if r.Envs[j].Key == "" {
				return fmt.Errorf("%s: credentials[%d].envs[%d]: key is required", id, i, j)
			}
		}
		if seen[r.Shape] == nil {
			seen[r.Shape] = map[string]struct{}{}
		}
		for _, f := range r.Fields() {
			if !envNamePattern.MatchString(f.Env) {
				return fmt.Errorf("%s: credentials[%d]: env %q must match %s", id, i, f.Env, envNamePattern.String())
			}
			if strings.HasPrefix(f.Env, "GIBSON_") {
				return fmt.Errorf("%s: credentials[%d]: env %q would shadow a launcher variable", id, i, f.Env)
			}
			if _, dup := seen[r.Shape][f.Env]; dup {
				return fmt.Errorf("%s: credentials[%d]: env %q is declared twice for shape %q", id, i, f.Env, r.Shape)
			}
			seen[r.Shape][f.Env] = struct{}{}
		}
	}
	return nil
}

func validateConnector(id string, s ConnectorSpec) error {
	switch s.Shape {
	case connectorv1alpha1.ConnectorShapeRemote:
		if s.Endpoint == "" {
			return fmt.Errorf("%s: a Remote connector needs an endpoint", id)
		}
		if s.Image != "" {
			return fmt.Errorf("%s: a Remote connector must not set image", id)
		}
	case connectorv1alpha1.ConnectorShapeHosted:
		if s.Image == "" {
			return fmt.Errorf("%s: a Hosted connector needs an image", id)
		}
		if s.Endpoint != "" {
			return fmt.Errorf("%s: a Hosted connector must not set endpoint", id)
		}
		if err := requireFirstPartyImageDigest(id, s.Image); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s: shape %q must be Hosted or Remote", id, s.Shape)
	}
	switch s.Auth {
	case connectorv1alpha1.ConnectorAuthNone, connectorv1alpha1.ConnectorAuthSecret, connectorv1alpha1.ConnectorAuthOAuth:
	default:
		return fmt.Errorf("%s: auth %q must be none, secret, or oauth", id, s.Auth)
	}
	return nil
}

// catalog is the parsed, validated set. Built once at package init; a parse or
// validation error is a build/ship defect, so init panics.
var catalog = mustLoad(manifestFS)

func mustLoad(fsys fs.FS) []Manifest {
	entries, err := load(fsys)
	if err != nil {
		panic("componentcatalog: " + err.Error())
	}
	return entries
}

// load parses every manifests/*.yaml into a validated Manifest, sorted by
// (kind, id) so the order is stable.
func load(fsys fs.FS) ([]Manifest, error) {
	files, err := fs.Glob(fsys, "manifests/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("glob manifests: %w", err)
	}
	entries := make([]Manifest, 0, len(files))
	seen := make(map[string]string, len(files))
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		var m Manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		key := m.Kind + "/" + m.ID
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s: duplicate component %q (also in %s)", f, key, prev)
		}
		seen[key] = f
		entries = append(entries, m)
	}
	if len(entries) == 0 {
		return nil, errors.New("no component manifests found")
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].ID < entries[j].ID
	})
	return entries, nil
}

// Ref is a (kind, id) pair identifying a catalog component. Its FGA object is
// authz.ComponentObject(Kind, ID) = "component:<kind>/<id>".
type Ref struct {
	Kind string
	ID   string
}

// List returns every parsed manifest, all kinds.

// Refs returns the (kind, id) of every catalog component — the input to the
// platform_enabled seeder, which seeds one tuple per ref.
func Refs() []Ref {
	out := make([]Ref, 0, len(catalog))
	for _, m := range catalog {
		out = append(out, Ref{Kind: m.Kind, ID: m.ID})
	}
	return out
}

// ImageRef is a catalog component together with the image it runs, for the
// supply-chain verifier. Kinds that name no image (a connector wrapping a
// remote MCP endpoint, say) are absent rather than present with an empty image,
// so a caller cannot mistake "declares no image" for "declares an empty one".
type ImageRef struct {
	Kind  string
	ID    string
	Image string
}

// ImageRefs returns every catalog component that names an image. The daemon
// verifies these signatures before seeding platform_enabled (ADR-0015 runtime
// verification, gibson#1639): the platform must not offer a component it cannot
// show was built by the release pipeline.
func ImageRefs() []ImageRef {
	out := make([]ImageRef, 0, len(catalog))
	for _, m := range catalog {
		var image string
		switch {
		case m.tool != nil:
			image = m.tool.Image
		case m.agent != nil:
			image = m.agent.Image
		case m.plugin != nil:
			image = m.plugin.Image
		case m.connector != nil:
			image = m.connector.Image
		}
		if image == "" {
			continue
		}
		out = append(out, ImageRef{Kind: m.Kind, ID: m.ID, Image: image})
	}
	return out
}

// ---- connector projection (preserves the connector consumers) ----

// ConnectorEntry is the connector-kind view a catalog manifest projects to, so
// ConnectorService/discovery keep a connector-shaped API after generalization.
type ConnectorEntry struct {
	ID                 string
	DisplayName        string
	Description        string
	EgressAllow        []string
	Vendor             string
	Shape              connectorv1alpha1.ConnectorShape
	Image              string
	Endpoint           string
	Transport          connectorv1alpha1.ConnectorTransport
	Auth               connectorv1alpha1.ConnectorAuthKind
	OAuthScope         string
	DefaultInstanceURL string
}

func (m Manifest) toConnectorEntry() ConnectorEntry {
	s := m.connector
	return ConnectorEntry{
		ID:                 m.ID,
		DisplayName:        m.DisplayName,
		Description:        m.Description,
		EgressAllow:        m.EgressAllow,
		Vendor:             s.Vendor,
		Shape:              s.Shape,
		Image:              s.Image,
		Endpoint:           s.Endpoint,
		Transport:          s.Transport,
		Auth:               s.Auth,
		OAuthScope:         s.OAuthScope,
		DefaultInstanceURL: s.DefaultInstanceURL,
	}
}

// ListConnectors returns the connector-kind entries, connector-shaped.
func ListConnectors() []ConnectorEntry {
	out := make([]ConnectorEntry, 0, len(catalog))
	for _, m := range catalog {
		if m.Kind == authz.KindConnector {
			out = append(out, m.toConnectorEntry())
		}
	}
	return out
}

// LookupConnector returns the connector entry with the given id.
// LookupEgress returns the egressAllow ceiling declared for the catalog
// component of the given kind and id, and whether such a component is listed.
// An agent's ceiling is applied to the setec egress of its tool dispatches
// (ADR-0015).
func LookupEgress(kind, id string) ([]string, bool) {
	for i := range catalog {
		if catalog[i].Kind == kind && catalog[i].ID == id {
			return catalog[i].EgressAllow, true
		}
	}
	return nil, false
}

func LookupConnector(id string) (ConnectorEntry, error) {
	for _, m := range catalog {
		if m.Kind == authz.KindConnector && m.ID == id {
			return m.toConnectorEntry(), nil
		}
	}
	return ConnectorEntry{}, fmt.Errorf("connector catalog: no entry %q", id)
}

// ---- agent projection (feeds the sandboxed-agent launch-spec resolver) ----

// AgentEntry is the agent-kind view a catalog manifest projects to, so a
// launch-spec resolver reads an agent's hosting and policy without touching the
// internal AgentSpec pointer. It mirrors ConnectorEntry.
type AgentEntry struct {
	ID          string
	DisplayName string
	Description string
	// Image is the digest-pinned agent OCI image (ADR-0015 decision 9).
	Image string
	// Runtime is the workload hosting (process | pod | setec).
	Runtime string
	// Model is the manifest's default slot-LLM policy.
	Model string
	// MinContextWindow is the smallest context window the agent's model must
	// have, in tokens. Zero means no floor (gibson#1692).
	MinContextWindow int
	// BudgetLimit is the agent's budget ceiling.
	BudgetLimit int
	// EgressAllow is the agent's egress ceiling (ADR-0016 decision 2/5).
	EgressAllow []string
	// Command is the one-shot sandbox launch command (the manifest's
	// `command`, shell split). setec refuses a launch with no command, so a
	// sandboxed agent's manifest must declare one.
	Command []string
	// MemberCommand is the launch command for the member shape, shell split.
	// Empty means this agent has no member driver and cannot join a bank.
	MemberCommand []string
	// MaxJobsInFlight is how many jobs one instance holds at once. Zero means
	// the agent states none and one is assumed.
	MaxJobsInFlight int32
	// Resources is the manifest's sandbox size; zero fields take the resolver defaults.
	Resources AgentResources
	// Credentials the launch must inject from the dispatching tenant's
	// provider configuration (gibson#1621).
	Credentials []CredentialRequirement
	// DispatchMode is the manifest's launch policy: "" (route by registry
	// trust) or DispatchModeSandboxed (force the sandbox launch). The harness
	// reads it to route a launched-on-dispatch platform agent to the sandbox
	// regardless of registry trust (ADR-0016).
	DispatchMode string
}

func (m Manifest) toAgentEntry() AgentEntry {
	s := m.agent
	return AgentEntry{
		ID:               m.ID,
		DisplayName:      m.DisplayName,
		Description:      m.Description,
		Image:            s.Image,
		Runtime:          s.Runtime,
		Model:            s.Model,
		MinContextWindow: s.MinContextWindow,
		BudgetLimit:      s.BudgetLimit,
		EgressAllow:      m.EgressAllow,
		DispatchMode:     s.DispatchMode,
		Credentials:      s.Credentials,
		Command:          strings.Fields(s.Command),
		MemberCommand:    strings.Fields(s.MemberCommand),
		MaxJobsInFlight:  s.MaxJobsInFlight,
		Resources:        s.Resources,
	}
}

// LookupAgent returns the agent-kind entry with the given id, and whether such
// an agent is listed. The sandboxed-agent launch-spec resolver (gibson#1597)
// reads Image, Model and EgressAllow from it to build one agent launch
// (ADR-0016). A missing agent returns ok=false so the resolver fails closed and
// the harness denies the dispatch.
func LookupAgent(id string) (AgentEntry, bool) {
	return lookupAgent(catalog, id)
}

// ToolEntry is a resolved `kind: tool` catalog manifest — everything a caller
// needs to build the tool's setec launch (ADR-0017). It replaces what the
// retired refresher used to synthesise from `--list-tools`.
type ToolEntry struct {
	ID          string
	DisplayName string
	Description string
	// Image is the digest-pinned tool image (usually the shared executor).
	Image string
	// Command is the launch command (the manifest `command`, shell-split).
	Command []string
	// ContentTrust is "trusted" | "untrusted" (ADR-0010).
	ContentTrust string
	// DispatchMode is "sandboxed" | "agent" | "plugin".
	DispatchMode string
	// EgressAllow is the tool's egress ceiling (envelope-level).
	EgressAllow []string
	// Resources is the manifest's sandbox size; zero fields take defaults.
	Resources AgentResources
}

func (m Manifest) toToolEntry() ToolEntry {
	s := m.tool
	return ToolEntry{
		ID:           m.ID,
		DisplayName:  m.DisplayName,
		Description:  m.Description,
		Image:        s.Image,
		Command:      strings.Fields(s.Command),
		ContentTrust: s.ContentTrust,
		DispatchMode: s.DispatchMode,
		EgressAllow:  m.EgressAllow,
		Resources:    s.Resources,
	}
}

func lookupTool(entries []Manifest, id string) (ToolEntry, bool) {
	for i := range entries {
		if entries[i].Kind == authz.KindTool && entries[i].ID == id {
			return entries[i].toToolEntry(), true
		}
	}
	return ToolEntry{}, false
}

// LookupTool resolves an embedded `kind: tool` manifest by id.
func LookupTool(id string) (ToolEntry, bool) {
	return lookupTool(catalog, id)
}

// lookupAgent projects the agent entry with the given id out of the given
// manifest set. It is split from LookupAgent so a test can project a synthetic
// agent manifest without shipping one into the embedded catalog.
func lookupAgent(entries []Manifest, id string) (AgentEntry, bool) {
	for i := range entries {
		if entries[i].Kind == authz.KindAgent && entries[i].ID == id {
			return entries[i].toAgentEntry(), true
		}
	}
	return AgentEntry{}, false
}

// BuildConnectorInstance builds the ConnectorInstance the operator reconciles
// for one connector entry in one tenant namespace.
func (e ConnectorEntry) BuildConnectorInstance(namespace string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      e.ID,
			Namespace: namespace,
			Labels: map[string]string{
				"gibson.zeroroot.ai/connector": e.ID,
				"app.kubernetes.io/managed-by": "gibson-connector-service",
				"app.kubernetes.io/part-of":    "gibson",
			},
		},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector:   e.ID,
			CatalogRef:  e.ID,
			Shape:       e.Shape,
			Image:       e.Image,
			Endpoint:    e.Endpoint,
			Transport:   e.Transport,
			Runtime:     connectorv1alpha1.ConnectorRuntimePod,
			EgressAllow: e.EgressAllow,
			Auth:        e.Auth,
		},
	}
}
