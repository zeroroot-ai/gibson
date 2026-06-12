// Package connector launches hosted MCP connectors as setec sandboxes
// (ADR-0048 Option 1, gibson#684).
//
// A connector is a vendor MCP server run unmodified behind the generic
// MCP-bridge runner image (gibson-mcp-bridge-runner). The launcher compiles a
// sandboxed.LaunchRequest from the connector manifest: the runner image, the
// manifest delivered inline as base64 env, the one-time capability-grant
// bootstrap token, and an egress allow-list confining the sandbox to the
// platform endpoints plus the manifest-declared vendor targets.
//
// The launcher uses only setec's generic primitives via the existing
// sandboxed.SandboxClient seam — no MCP- or connector-specific code crosses
// into setec.
package connector

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdkconnector "github.com/zeroroot-ai/sdk/mcpbridge/connector"

	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
	"github.com/zeroroot-ai/sdk/auth"
)

// Env var names consumed by the mcp-bridge-runner image.
const (
	envManifestB64    = "GIBSON_CONNECTOR_MANIFEST_B64"
	envPlatformURL    = "GIBSON_URL"
	envBootstrapToken = "GIBSON_BOOTSTRAP_TOKEN"
)

// Defaults applied when Config leaves the corresponding field zero.
const (
	defaultVCPU    = 1
	defaultMemory  = "512Mi"
	defaultTimeout = 8 * time.Hour
)

// Config is the constructor input for the Launcher.
type Config struct {
	// Client launches sandboxes. Required.
	Client sandboxed.SandboxClient

	// RunnerImage is the OCI reference of the generic MCP-bridge runner
	// (ghcr.io/zeroroot-ai/gibson-mcp-bridge-runner:<tag>). Required.
	RunnerImage string

	// PlatformURL is the gibson platform base URL the bridge dials from
	// inside the sandbox (capability-grant registration, ComponentService,
	// GetCredential). Required.
	PlatformURL string

	// PlatformEgress is the allow-list entries every connector sandbox needs
	// regardless of vendor: the platform endpoints derived from PlatformURL
	// plus the package registries the runner fetches vendors from
	// (registry.npmjs.org, pypi.org, …). Required, non-empty — an empty list
	// would strand the bridge with no route to the control plane.
	PlatformEgress []sandboxed.EgressRule

	// VCPU / Memory bound the sandbox. Defaults: 1 vCPU, 512Mi.
	VCPU   int32
	Memory string

	// Timeout is the sandbox lifecycle ceiling. Connectors are persistent;
	// this is a safety net, not a call budget. Default 8h.
	Timeout time.Duration

	// Admit, when set, is consulted before each launch to enforce the
	// plan-tier connector-instance budget (ADR-0047 facet 3). It returns a
	// codes.ResourceExhausted error when the tenant is already at its limit,
	// which Launch surfaces unchanged. Nil disables budget enforcement
	// (dev/kind clusters without a platform Postgres pool).
	Admit func(ctx context.Context, tenant auth.TenantID) error

	// Logger defaults to slog.Default.
	Logger *slog.Logger
}

// Launcher launches hosted connectors. Construct with New.
type Launcher struct {
	cfg Config
}

// New validates cfg and constructs a Launcher.
func New(cfg Config) (*Launcher, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("connector.New: Client is required")
	}
	if cfg.RunnerImage == "" {
		return nil, fmt.Errorf("connector.New: RunnerImage is required")
	}
	if cfg.PlatformURL == "" {
		return nil, fmt.Errorf("connector.New: PlatformURL is required")
	}
	if len(cfg.PlatformEgress) == 0 {
		return nil, fmt.Errorf("connector.New: PlatformEgress is required " +
			"(the bridge needs a route to the control plane and package registries)")
	}
	if cfg.VCPU <= 0 {
		cfg.VCPU = defaultVCPU
	}
	if cfg.Memory == "" {
		cfg.Memory = defaultMemory
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Launcher{cfg: cfg}, nil
}

// Launch starts one hosted connector sandbox. connectorYAML is the validated
// connector manifest; bootstrapToken is the single-use capability-grant token
// minted at registration (it reaches the process environment of the runner
// and is never logged). Returns the setec sandbox id.
func (l *Launcher) Launch(ctx context.Context, tenant auth.TenantID, connectorYAML []byte, bootstrapToken string) (string, error) {
	m, err := sdkconnector.LoadBytes(connectorYAML)
	if err != nil {
		return "", fmt.Errorf("connector: parse manifest: %w", err)
	}
	if m.Spec.Transport != sdkconnector.TransportStdio {
		// Option 1 hosts package-distributed (stdio) vendors only; http
		// transport means the vendor is already running elsewhere and needs
		// no sandbox.
		return "", fmt.Errorf("connector: hosted launch supports stdio transport only, got %q", m.Spec.Transport)
	}
	if bootstrapToken == "" {
		return "", fmt.Errorf("connector: bootstrap token is required for hosted launch")
	}

	// Plan-tier connector-instance budget (ADR-0047 facet 3). Enforced before
	// the sandbox is created so an over-budget tenant gets an explicit capacity
	// error and never over-provisions.
	if l.cfg.Admit != nil {
		if err := l.cfg.Admit(ctx, tenant); err != nil {
			return "", fmt.Errorf("connector: launch denied for %q: %w", m.Metadata.Name, err)
		}
	}

	// Egress allow-list: platform endpoints + manifest-declared vendor
	// targets. Everything else is unreachable from inside the sandbox.
	egress := make([]sandboxed.EgressRule, 0, len(l.cfg.PlatformEgress)+len(m.Spec.Egress))
	egress = append(egress, l.cfg.PlatformEgress...)
	for _, e := range m.Spec.Egress {
		egress = append(egress, sandboxed.EgressRule{Host: e.Host, Port: uint32(e.Port)})
	}

	resp, err := l.cfg.Client.Launch(ctx, sandboxed.LaunchRequest{
		Image: l.cfg.RunnerImage,
		// The image ENTRYPOINT is the runner binary; no command override.
		Env: map[string]string{
			envManifestB64:    base64.StdEncoding.EncodeToString(connectorYAML),
			envPlatformURL:    l.cfg.PlatformURL,
			envBootstrapToken: bootstrapToken,
		},
		VCPU:    l.cfg.VCPU,
		Memory:  l.cfg.Memory,
		Tenant:  tenant.String(),
		Timeout: l.cfg.Timeout,
		Egress:  egress,
	})
	if err != nil {
		return "", fmt.Errorf("connector: launch sandbox for %q: %w", m.Metadata.Name, err)
	}

	l.cfg.Logger.Info("connector: hosted sandbox launched",
		"connector", m.Metadata.Name,
		"tenant", tenant.String(),
		"sandbox_id", resp.SandboxID,
		"egress_rules", len(egress),
	)
	return resp.SandboxID, nil
}

// Terminate stops a hosted connector sandbox by id, used on disable
// (gibson#723). It is idempotent: an empty id or an already-gone sandbox
// (setec reports NotFound) is a safe no-op, so a teardown that races sandbox
// expiry does not error.
func (l *Launcher) Terminate(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return nil
	}
	if err := l.cfg.Client.Kill(ctx, sandboxID); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return fmt.Errorf("connector: terminate sandbox %q: %w", sandboxID, err)
	}
	l.cfg.Logger.Info("connector: hosted sandbox terminated", "sandbox_id", sandboxID)
	return nil
}
