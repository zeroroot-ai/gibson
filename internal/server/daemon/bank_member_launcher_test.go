// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/sdk/auth"
)

// memberSandboxClient records the one launch a member test makes.
type memberSandboxClient struct {
	launched []sandboxed.LaunchRequest
	killed   []string
}

func (c *memberSandboxClient) Launch(_ context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	c.launched = append(c.launched, req)
	return sandboxed.LaunchResponse{SandboxID: "sbx-1", Runtime: "gvisor"}, nil
}

func (c *memberSandboxClient) StreamLogs(context.Context, string) (sandboxed.LogStream, error) {
	return eofLogs{}, nil
}

func (c *memberSandboxClient) Wait(ctx context.Context, _ string) (sandboxed.WaitResponse, error) {
	<-ctx.Done()
	return sandboxed.WaitResponse{}, fmt.Errorf("wait: %w", ctx.Err())
}

func (c *memberSandboxClient) Kill(_ context.Context, id string) error {
	c.killed = append(c.killed, id)
	return nil
}

type eofLogs struct{}

func (eofLogs) Recv() ([]byte, error) { return nil, io.EOF }
func (eofLogs) Close() error          { return nil }

// memberSpecResolver records the request and answers a member spec.
type memberSpecResolver struct {
	got harness.AgentLaunchRequest
	err error
}

func (r *memberSpecResolver) ResolveAgentLaunchSpec(ctx context.Context, req harness.AgentLaunchRequest) (sandboxed.AgentLaunchSpec, error) {
	r.got = req
	if r.err != nil {
		return sandboxed.AgentLaunchSpec{}, r.err
	}
	if auth.TenantStringFromContext(ctx) == "" {
		return sandboxed.AgentLaunchSpec{}, errors.New("the resolver needs the tenant on the context")
	}
	return sandboxed.AgentLaunchSpec{
		Image: "ghcr.io/x/claude@sha256:abc", Command: []string{"node", "/app/dist/member-main.js"},
		Mode: req.Mode, Model: "claude-sonnet-4", SandboxClass: "agent",
	}, nil
}

func memberTestDaemon(t *testing.T, client sandboxed.SandboxClient, resolver harness.AgentLaunchSpecResolver) *daemonImpl {
	t.Helper()
	launcher, err := sandboxed.NewAgentLauncher(sandboxed.AgentLauncherConfig{Client: client, Tenant: "infra", SandboxClass: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	return &daemonImpl{
		agentLauncher:           launcher,
		agentLaunchSpecResolver: resolver,
		agentCallbackEndpoint:   "callback.gibson:443",
		cgMinter:                testCGMinter(t),
	}
}

func testBankForLaunch() *bank.Bank {
	return &bank.Bank{
		ID: "bank-1", Name: "nightly", AgentName: "claude", LoginShape: bank.LoginShapeAPIKey,
		Model: "claude-opus-4", MaxJobsInFlight: 2, StaleLimit: 90 * time.Minute, DesiredCount: 1,
	}
}

// TestMemberLauncher_LaunchesWithTheBaseGrantAndTheMemberContract asserts the
// whole launch: the member shape is resolved for the caller's tenant, the base
// grant is scoped to the bank and the member's run, and the driver's contract
// variables are on the sandbox.
func TestMemberLauncher_LaunchesWithTheBaseGrantAndTheMemberContract(t *testing.T) {
	t.Setenv(envPublicURL, "https://app.zeroroot.example")
	client := &memberSandboxClient{}
	resolver := &memberSpecResolver{}
	d := memberTestDaemon(t, client, resolver)
	l := &memberLauncher{daemon: d}

	launched, err := l.LaunchMember(context.Background(), "acme", testBankForLaunch(), "m-1")
	if err != nil {
		t.Fatalf("LaunchMember: %v", err)
	}
	if launched.SandboxID != "sbx-1" || launched.MissionID != "bank-1" || launched.MissionRunID == "" || launched.AgentRunID == "" {
		t.Fatalf("launched = %+v", launched)
	}
	if resolver.got.Mode != harness.ModeMember || resolver.got.AgentName != "claude" || resolver.got.LoginShape != "api_key" {
		t.Errorf("resolver asked for %+v", resolver.got)
	}

	req := client.launched[0]
	for k, want := range map[string]string{
		envMemberID: "m-1", envBankID: "bank-1", envPlatformURL: "https://app.zeroroot.example",
		envLoginShape: "api_key", envClaudeModel: "claude-opus-4", envJobCap: "2",
		envJobStaleLimitMS: "5400000", envHeartbeatMS: "10000",
		"GIBSON_INSTANCE_MODE": "member", "GIBSON_CALLBACK_ENDPOINT": "callback.gibson:443",
		"GIBSON_MISSION_ID": "bank-1", "GIBSON_MISSION_RUN_ID": launched.MissionRunID, "GIBSON_MODEL": "claude-opus-4",
	} {
		if req.Env[k] != want {
			t.Errorf("env[%s] = %q, want %q", k, req.Env[k], want)
		}
	}

	verifier := capabilitygrant.NewLocalVerifier(func() *capabilitygrant.Minter { return d.cgMinter })
	claims, err := verifier.Verify(context.Background(), req.Env["GIBSON_CG_JWT"])
	if err != nil {
		t.Fatalf("the base grant must verify: %v", err)
	}
	if claims.MissionID != "bank-1" || claims.TaskID != launched.MissionRunID || claims.Tenant.String() != "acme" {
		t.Errorf("grant scope = %+v, want the bank and the member's run", claims)
	}
	assertSameSet(t, claims.AllowedRPCs, harness.MemberBaseGrantRPCs())
	for _, rpc := range claims.AllowedRPCs {
		if strings.HasSuffix(rpc, "/SubmitFinding") || strings.HasSuffix(rpc, "/GetCredential") {
			t.Errorf("the base grant must not carry %s", rpc)
		}
	}
}

func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("allowed_rpcs = %v, want %v", got, want)
	}
	set := map[string]bool{}
	for _, w := range want {
		set[w] = true
	}
	for _, g := range got {
		if !set[g] {
			t.Errorf("%s is on the grant but not on the base set", g)
		}
	}
}

// TestMemberLauncher_RefusesWhatItCannotDo: a resolve failure is reported
// before anything is launched, and a daemon with no launcher, no resolver or no
// signing key says so.
func TestMemberLauncher_RefusesWhatItCannotDo(t *testing.T) {
	client := &memberSandboxClient{}
	d := memberTestDaemon(t, client, &memberSpecResolver{err: errors.New("no manifest")})
	l := &memberLauncher{daemon: d}
	if _, err := l.LaunchMember(context.Background(), "acme", testBankForLaunch(), "m-1"); err == nil {
		t.Error("a resolve failure must be reported")
	}
	if len(client.launched) != 0 {
		t.Error("nothing may launch when the spec cannot be resolved")
	}

	for name, d := range map[string]*daemonImpl{
		"no launcher": {agentLaunchSpecResolver: &memberSpecResolver{}, cgMinter: testCGMinter(t)},
		"no resolver": {agentLauncher: d.agentLauncher, cgMinter: testCGMinter(t)},
		"no minter":   {agentLauncher: d.agentLauncher, agentLaunchSpecResolver: &memberSpecResolver{}},
	} {
		l := &memberLauncher{daemon: d}
		if _, err := l.LaunchMember(context.Background(), "acme", testBankForLaunch(), "m-1"); err == nil {
			t.Errorf("%s: the launch must be refused", name)
		}
		if err := l.StopMember(context.Background(), "acme", &bank.Member{ID: "m-1", SandboxID: "sbx-1"}); err == nil {
			t.Errorf("%s: the stop must be refused", name)
		}
	}
}

// TestMemberLauncher_StopMemberKillsTheSandbox asserts the teardown reaches the
// sandbox, and that a member with no sandbox is a reported defect.
func TestMemberLauncher_StopMemberKillsTheSandbox(t *testing.T) {
	client := &memberSandboxClient{}
	l := &memberLauncher{daemon: memberTestDaemon(t, client, &memberSpecResolver{})}
	if err := l.StopMember(context.Background(), "acme", &bank.Member{ID: "m-1", SandboxID: "sbx-7"}); err != nil {
		t.Fatalf("StopMember: %v", err)
	}
	if len(client.killed) != 1 || client.killed[0] != "sbx-7" {
		t.Fatalf("killed = %v", client.killed)
	}
	if err := l.StopMember(context.Background(), "acme", &bank.Member{ID: "m-1"}); err == nil {
		t.Error("a member with no sandbox must be reported")
	}
}

// TestStartBankRunner_RefusesWithoutItsSeams asserts that a daemon that cannot
// launch a member does not start a reconciler that would fail every pass.
func TestStartBankRunner_RefusesWithoutItsSeams(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger()}
	d.startBankRunner(context.Background())
	if d.bankRunner != nil {
		t.Fatal("a daemon with no pool must not start the bank runner")
	}
}

// TestMemberEnv_CarriesTheContract asserts the driver's variables and that a
// bank with no model leaves the model to the manifest.
func TestMemberEnv_CarriesTheContract(t *testing.T) {
	b := testBankForLaunch()
	env := memberEnv(b, "m-9", "")
	if _, has := env[envClaudeModel]; has {
		t.Error("no model means no model variable")
	}
	if env[envJobCap] != "2" || env[envJobStaleLimitMS] != "5400000" || env[envMemberID] != "m-9" {
		t.Errorf("env = %v", env)
	}
}

type staticTenants struct{}

func (staticTenants) ListTenants(context.Context) ([]auth.TenantID, error) { return nil, nil }

// TestBuildBankRunner_NeedsThePoolAndTheSeams asserts that the runner is built
// only when every seam is present, and that each missing one is named.
func TestBuildBankRunner_NeedsThePoolAndTheSeams(t *testing.T) {
	d := memberTestDaemon(t, &memberSandboxClient{}, &memberSpecResolver{})
	d.logger = testObsLogger()
	if _, err := d.buildBankRunner(staticTenants{}); err == nil {
		t.Fatal("no pool must refuse")
	}

	d.pool = &mockPool{conn: minimalConn()}
	runner, err := d.buildBankRunner(staticTenants{})
	if err != nil || runner == nil {
		t.Fatalf("buildBankRunner = %v, %v", runner, err)
	}
	if _, err := d.buildBankRunner(nil); err == nil {
		t.Fatal("no tenant source must refuse")
	}

	d.cgMinter = nil
	if _, err := d.buildBankRunner(staticTenants{}); err == nil {
		t.Fatal("no signing key must refuse")
	}
}

// TestTenantIDsOf_SkipsDeletingAndMalformedTenants asserts the reconciler's
// tenant list carries live, well-formed tenant ids only.
func TestTenantIDsOf_SkipsDeletingAndMalformedTenants(t *testing.T) {
	live := unstructured.Unstructured{}
	live.SetName("acme")
	going := unstructured.Unstructured{}
	going.SetName("globex")
	now := metav1.Now()
	going.SetDeletionTimestamp(&now)
	bad := unstructured.Unstructured{}
	bad.SetName("Not A Tenant!")
	ids := tenantIDsOf([]unstructured.Unstructured{live, going, bad})
	if len(ids) != 1 || ids[0].String() != "acme" {
		t.Fatalf("ids = %v, want acme only", ids)
	}
}
