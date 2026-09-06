// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"

	bankengine "github.com/zeroroot-ai/gibson/internal/engine/bank"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/sdk/auth"
)

// The member environment contract, from the member driver's README
// (zeroroot-ai/zerocool-plugins, packages/claude-member). The grant, the
// callback endpoint, the mission ids and the model are injected by the
// launcher under their GIBSON_ names; these are the rest.
const (
	envMemberID          = "GIBSON_MEMBER_ID"
	envBankID            = "GIBSON_BANK_ID"
	envPlatformURL       = "GIBSON_PLATFORM_URL"
	envLoginShape        = "ZEROCOOL_LOGIN_SHAPE"
	envClaudeModel       = "ZEROCOOL_CLAUDE_MODEL"
	envJobCap            = "ZEROCOOL_JOB_CAP"
	envJobStaleLimitMS   = "ZEROCOOL_JOB_STALE_LIMIT_MS"
	envHeartbeatMS       = "ZEROCOOL_HEARTBEAT_MS"
	envPublicURL         = "GIBSON_PUBLIC_URL"
	memberHeartbeatEvery = 10 * time.Second
)

// memberLauncher is the mechanism half of the bank reconciler (ADR-0019
// decision 1, gibson#1709): it makes one member exist or stop existing.
//
// A member backs no mission of its own. The bank is its origin: the base
// grant is scoped to the bank, the member's run id is the identity every
// member callback resolves (gibson#1711), and the jobs it serves are the
// missions' work. Its seams resolve per call because the launcher, the
// resolver and the signing key are all built during Start.
type memberLauncher struct {
	daemon *daemonImpl
}

var _ bankengine.MemberLauncher = (*memberLauncher)(nil)

func (l *memberLauncher) seams() (*sandboxed.AgentLauncher, harness.AgentLaunchSpecResolver, *capabilitygrant.Minter, error) {
	d := l.daemon
	switch {
	case d.agentLauncher == nil || d.agentLaunchSpecResolver == nil:
		return nil, nil, nil, errors.New("sandboxed agent dispatch is not wired, so this daemon cannot launch a member")
	case d.cgMinter == nil:
		return nil, nil, nil, errors.New("the daemon has no signing key, so it cannot mint a member's base grant")
	}
	return d.agentLauncher, d.agentLaunchSpecResolver, d.cgMinter, nil
}

// LaunchMember resolves the member shape of the bank's agent, mints the base
// grant, and starts the sandbox. It returns as soon as the sandbox is admitted.
func (l *memberLauncher) LaunchMember(ctx context.Context, tenantID string, b *bank.Bank, memberID string) (bankengine.LaunchedMember, error) {
	launcher, resolver, minter, err := l.seams()
	if err != nil {
		return bankengine.LaunchedMember{}, err
	}
	// The resolver reads the tenant from the context, the way every
	// tenant-scoped decision does, so the launch cannot name another tenant.
	tctx := auth.ContextWithTenantString(ctx, tenantID)
	spec, err := resolver.ResolveAgentLaunchSpec(tctx, harness.AgentLaunchRequest{
		AgentName:  b.AgentName,
		LoginShape: string(b.LoginShape),
		Mode:       harness.ModeMember,
	})
	if err != nil {
		return bankengine.LaunchedMember{}, fmt.Errorf("resolve the member shape of %q: %w", b.AgentName, err)
	}
	if b.Model != "" {
		// A bank may name its model. The manifest's and the tenant's default
		// stand when it does not.
		spec.Model = b.Model
	}

	// The member's run id is minted here, not by setec: it is the key every
	// member callback resolves the member by, and it has to be on the grant
	// before the sandbox exists.
	runID := string(types.NewID())
	grant, err := minter.Mint(capabilitygrant.MintRequest{
		Subject:        "component:agent:" + b.AgentName,
		Tenant:         tenantID,
		MissionID:      b.ID,
		TaskID:         runID,
		RecipientClass: "agent",
		AllowedRPCs:    harness.MemberBaseGrantRPCs(),
	})
	if err != nil {
		return bankengine.LaunchedMember{}, fmt.Errorf("mint the base grant of member %s: %w", memberID, err)
	}

	run, err := launcher.LaunchMember(tctx, spec, sandboxed.AgentDispatch{
		Grant:            grant,
		CallbackEndpoint: l.daemon.agentCallbackEndpoint,
		MissionID:        b.ID,
		MissionRunID:     runID,
		AgentRunID:       memberID,
		Tenant:           tenantID,
		AgentName:        b.AgentName,
		Env:              memberEnv(b, memberID, spec.Model),
	})
	if err != nil {
		return bankengine.LaunchedMember{}, fmt.Errorf("launch member %s of bank %s: %w", memberID, b.ID, err)
	}
	return bankengine.LaunchedMember{
		MissionID:    b.ID,
		MissionRunID: runID,
		AgentRunID:   run.RunID,
		SandboxID:    run.SandboxID,
	}, nil
}

// memberEnv is the member driver's contract beside the injected runtime keys.
func memberEnv(b *bank.Bank, memberID, model string) map[string]string {
	env := map[string]string{
		envMemberID:        memberID,
		envBankID:          b.ID,
		envPlatformURL:     os.Getenv(envPublicURL),
		envLoginShape:      string(b.LoginShape),
		envJobCap:          strconv.Itoa(int(b.MaxJobsInFlight)),
		envJobStaleLimitMS: strconv.FormatInt(b.StaleLimit.Milliseconds(), 10),
		envHeartbeatMS:     strconv.FormatInt(memberHeartbeatEvery.Milliseconds(), 10),
	}
	if model != "" {
		env[envClaudeModel] = model
	}
	return env
}

// StopMember ends a member's sandbox.
func (l *memberLauncher) StopMember(ctx context.Context, _ string, m *bank.Member) error {
	launcher, _, _, err := l.seams()
	if err != nil {
		return err
	}
	if m.SandboxID == "" {
		return fmt.Errorf("member %s names no sandbox, so there is nothing to stop", m.ID)
	}
	if err := launcher.StopSandbox(ctx, m.SandboxID); err != nil {
		return fmt.Errorf("stop member %s: %w", m.ID, err)
	}
	return nil
}

// startBankRunner builds the bank reconciler over the daemon's seams and starts
// it. A daemon that cannot launch a member (no data-plane pool, no sandboxed
// dispatch, no signing key, no tenant lister) logs why and serves everything
// else: a bank on such a daemon stays at zero members, visibly.
func (d *daemonImpl) startBankRunner(ctx context.Context) {
	tenants, err := d.bankTenantSource()
	if err != nil {
		d.logger.Warn(ctx, "bank reconciler not started: no tenant lister", "error", err)
		return
	}
	runner, err := d.buildBankRunner(tenants)
	if err != nil {
		d.logger.Warn(ctx, "bank reconciler not started", "error", err)
		return
	}
	d.bankRunner = runner
	go runner.Run(ctx)
	d.logger.Info(ctx, "bank reconciler started", "interval", bankengine.DefaultInterval.String())
}

// buildBankRunner assembles the reconciler and its runner. It is the part of
// startBankRunner a test can reach: every seam is checked here.
func (d *daemonImpl) buildBankRunner(tenants bankengine.TenantSource) (*bankengine.Runner, error) {
	if d.pool == nil {
		return nil, errors.New("the data-plane pool is unavailable, so there are no bank tables to read")
	}
	launcher := &memberLauncher{daemon: d}
	if _, _, _, err := launcher.seams(); err != nil {
		return nil, err
	}
	rec, err := bankengine.New(bankengine.Config{
		Store:    bank.NewPostgresStore(d.pool),
		Launcher: launcher,
		Jobs:     job.NewPostgresStore(d.pool),
		Logger:   d.logger.Slog(),
	})
	if err != nil {
		return nil, fmt.Errorf("build the bank reconciler: %w", err)
	}
	runner, err := bankengine.NewRunner(bankengine.RunnerConfig{
		Reconciler: rec, Tenants: tenants, Logger: d.logger.Slog(),
	})
	if err != nil {
		return nil, fmt.Errorf("build the bank runner: %w", err)
	}
	return runner, nil
}

// bankTenantSource lists the tenants whose banks are reconciled, from the
// Kubernetes Tenant CRs.
//
// It reads the CRs itself rather than through the admin pool's lister: the
// admin pool is the cross-tenant data-plane seam and only the admin surfaces
// may import it (database-per-tenant Requirement 11.5). The reconciler needs
// tenant NAMES, not a cross-tenant connection, and it takes each tenant's own
// pool connection the ordinary way.
func (d *daemonImpl) bankTenantSource() (bankengine.TenantSource, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("kube config: %w", err)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kube dynamic client: %w", err)
	}
	return &tenantCRLister{client: client}, nil
}

// tenantGVR is the Tenant CRD the tenant operator reconciles.
var tenantGVR = schema.GroupVersionResource{Group: "gibson.zeroroot.ai", Version: "v1alpha1", Resource: "tenants"}

// tenantCRLister lists Tenant CRs that are not being deleted.
type tenantCRLister struct {
	client dynamic.Interface
}

func (l *tenantCRLister) ListTenants(ctx context.Context) ([]auth.TenantID, error) {
	list, err := l.client.Resource(tenantGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list Tenant CRs: %w", err)
	}
	return tenantIDsOf(list.Items), nil
}

// tenantIDsOf reads the tenant ids out of Tenant CRs, skipping any being
// deleted and any whose name is not a tenant id.
func tenantIDsOf(items []unstructured.Unstructured) []auth.TenantID {
	out := make([]auth.TenantID, 0, len(items))
	for i := range items {
		if items[i].GetDeletionTimestamp() != nil {
			continue
		}
		tid, err := auth.NewTenantID(items[i].GetName())
		if err != nil {
			continue
		}
		out = append(out, tid)
	}
	return out
}
