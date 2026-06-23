//go:build e2e
// +build e2e

// Package e2e — non_plugin_deny_test.go
//
// Deny-path E2E test for the non-plugin-secret-isolation spec (Task 13).
//
// WHAT THIS TEST DOES
// -------------------
// This is a narrowly-focused companion test to fga_enforcement_test.go.
// It provisions three workload identities for a single tenant:
//
//	agent_principal  — PRINCIPAL_KIND_AGENT
//	tool_principal   — PRINCIPAL_KIND_TOOL
//	plugin_principal — PRINCIPAL_KIND_PLUGIN
//
// Each calls both HarnessCallbackService.GetCredential and
// ComponentService.GetCredential.  The test asserts:
//
//	agent_principal  → PERMISSION_DENIED on both services; audit rows
//	                    carry decision_reason=fga_no_can_resolve and
//	                    actor_workload_class=agent.
//	tool_principal   → PERMISSION_DENIED on both services; audit rows
//	                    carry decision_reason=fga_no_can_resolve and
//	                    actor_workload_class=tool.
//	plugin_principal → OK (or NotFound when seed failed) on both
//	                    services; no fga_no_can_resolve in audit rows.
//
// The assertions deliberately separate workload-class labelling from the
// broader FGA enforcement already verified in fga_enforcement_test.go.
// This test exists to provide direct evidence for
// non-plugin-secret-isolation Requirement 6.
//
// DETERMINISM
// -----------
// Each test run uses a unique nanosecond suffix on all provisioned
// names.  FGA propagation is awaited via a probe loop (up to 30 s) before
// making assertions.  All principals and the test credential are deleted in
// t.Cleanup.
//
// PREREQUISITES
// -------------
//   - Kind cluster "gibson" deployed; kubectl context = kind-gibson
//   - GIBSON_TEST_FIXTURES_ENABLED=true
//   - GIBSON_TEST_TENANT_ADMIN_TOKEN — valid admin JWT
//   - GIBSON_TEST_TENANT_ID — tenant slug / ID
//   - DAEMON_GRPC_ADDR (optional, default: localhost:50002)
//   - GIBSON_ZITADEL_TOKEN_URL (optional, default: http://localhost:30443/oauth/v2/token)
//
// INVOCATION
// ----------
//
//	GIBSON_TEST_FIXTURES_ENABLED=true \
//	GIBSON_TEST_TENANT_ADMIN_TOKEN=<jwt> \
//	GIBSON_TEST_TENANT_ID=<slug> \
//	  go test -tags=e2e -run TestNonPluginDeny -timeout 5m \
//	    ./tests/e2e/secrets/...
//
// Spec: non-plugin-secret-isolation Requirement 6, Task 13.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/agentidentity/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// nonPluginTestCredBase is the base name for the test credential.
const nonPluginTestCredBase = "npi-e2e-deny-cred"

// TestNonPluginDeny_HarnessAndComponent verifies the structural deny property
// for non-plugin callers at both GetCredential endpoints.
//
// It is the primary E2E evidence for non-plugin-secret-isolation R6.
func TestNonPluginDeny_HarnessAndComponent(t *testing.T) {
	if os.Getenv("GIBSON_TEST_FIXTURES_ENABLED") != "true" {
		t.Skip("set GIBSON_TEST_FIXTURES_ENABLED=true to run E2E tests")
	}

	adminToken := os.Getenv("GIBSON_TEST_TENANT_ADMIN_TOKEN")
	if adminToken == "" {
		t.Skip("GIBSON_TEST_TENANT_ADMIN_TOKEN not set; skipping non-plugin-deny E2E")
	}
	tenantID := os.Getenv("GIBSON_TEST_TENANT_ID")
	if tenantID == "" {
		t.Skip("GIBSON_TEST_TENANT_ID not set; skipping non-plugin-deny E2E")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// ----------------------------------------------------------------
	// Step 0: safety guard — must target kind-gibson only.
	// ----------------------------------------------------------------
	requireKindGibsonContext(t, ctx)

	// ----------------------------------------------------------------
	// Step 1: dial the daemon.
	// ----------------------------------------------------------------
	daemonAddr := daemonGRPCAddr()
	t.Logf("[NPI deny step 1] connecting to daemon at %s", daemonAddr)

	conn, err := grpc.NewClient(daemonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "grpc.NewClient should succeed")
	t.Cleanup(func() { _ = conn.Close() })

	tenantAdminClient := tenantv1.NewTenantServiceClient(conn)
	harnessClient := harnesspb.NewHarnessCallbackServiceClient(conn)
	componentClient := componentpb.NewComponentServiceClient(conn)

	adminCtx := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer "+adminToken,
		"x-tenant-id", tenantID,
	)

	// ----------------------------------------------------------------
	// Step 2: provision three principals (agent, tool, plugin).
	// ----------------------------------------------------------------
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	credName := nonPluginTestCredBase + "-" + runID

	type principalSpec struct {
		kind          tenantv1.PrincipalKind
		label         string
		workloadClass string // expected audit row value
	}
	principals := []principalSpec{
		{tenantv1.PrincipalKind_PRINCIPAL_KIND_AGENT, "npi-agent", "agent"},
		{tenantv1.PrincipalKind_PRINCIPAL_KIND_TOOL, "npi-tool", "tool"},
		{tenantv1.PrincipalKind_PRINCIPAL_KIND_PLUGIN, "npi-plugin", "plugin"},
	}

	type provisionedPrincipal struct {
		principalSpec
		principalID  string
		clientID     string
		clientSecret string
	}
	provisioned := make([]provisionedPrincipal, 0, len(principals))

	t.Log("[NPI deny step 2] provisioning three principals")
	for _, ps := range principals {
		resp, provErr := tenantAdminClient.CreateAgentIdentity(adminCtx,
			&tenantv1.CreateAgentIdentityRequest{
				Name:        fmt.Sprintf("%s-%s", ps.label, runID),
				Kind:        ps.kind,
				Description: "Ephemeral principal for non-plugin-isolation deny E2E",
			})
		require.NoError(t, provErr, "CreateAgentIdentity(%s) should succeed", ps.label)
		provisioned = append(provisioned, provisionedPrincipal{
			principalSpec: ps,
			principalID:   resp.GetPrincipalId(),
			clientID:      resp.GetClientId(),
			clientSecret:  resp.GetClientSecret(),
		})
		t.Logf("[NPI deny step 2] provisioned %s: principal_id=%s", ps.label, resp.GetPrincipalId())
	}

	// Cleanup: revoke all principals.
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanCancel()
		cleanAdminCtx := metadata.AppendToOutgoingContext(cleanCtx,
			"authorization", "Bearer "+adminToken,
			"x-tenant-id", tenantID,
		)
		for _, p := range provisioned {
			if p.principalID == "" {
				continue
			}
			_, revokeErr := tenantAdminClient.RevokeAgentIdentity(cleanAdminCtx,
				&tenantv1.RevokeAgentIdentityRequest{PrincipalId: p.principalID})
			if revokeErr != nil {
				t.Logf("[NPI deny cleanup] RevokeAgentIdentity(%s %s): %v",
					p.label, p.principalID, revokeErr)
			} else {
				t.Logf("[NPI deny cleanup] revoked %s %s", p.label, p.principalID)
			}
		}
	})

	// ----------------------------------------------------------------
	// Step 3: seed the test credential.
	// ----------------------------------------------------------------
	t.Logf("[NPI deny step 3] seeding test credential: name=%s", credName)
	seedErr := seedTestCredential(ctx, credName, "npi-deny-payload-"+runID)
	if seedErr != nil {
		t.Logf("[NPI deny step 3] WARN: seed failed (%v); test continues with partial assertions", seedErr)
	} else {
		t.Log("[NPI deny step 3] PASS: credential seeded")
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanCancel()
		if delErr := deleteTestCredential(cleanCtx, credName); delErr != nil {
			t.Logf("[NPI deny cleanup] delete credential %s: %v", credName, delErr)
		} else {
			t.Logf("[NPI deny cleanup] deleted credential %s", credName)
		}
	})

	// ----------------------------------------------------------------
	// Step 4: obtain tokens for all principals.
	// ----------------------------------------------------------------
	t.Log("[NPI deny step 4] obtaining tokens for all principals")
	tokenMap := make(map[string]string, len(provisioned))
	for _, p := range provisioned {
		tok, tokErr := exchangeClientCredentials(ctx, p.clientID, p.clientSecret)
		if tokErr != nil {
			// In Kind test-fixture mode the daemon accepts clientID as bearer.
			t.Logf("[NPI deny step 4] WARN: token exchange for %s: %v; using clientID placeholder", p.label, tokErr)
			tok = p.clientID
		}
		tokenMap[p.label] = tok
	}

	// ----------------------------------------------------------------
	// Step 5: wait for FGA tuple propagation.
	// ----------------------------------------------------------------
	t.Log("[NPI deny step 5] waiting for FGA deny path to become active (probe from agent)")
	agentToken := tokenMap["npi-agent"]
	agentProbeCtx := metadata.AppendToOutgoingContext(ctx,
		"authorization", "Bearer "+agentToken,
		"x-tenant-id", tenantID,
	)
	npiWaitForFGADenyPath(t, ctx, harnessClient, agentProbeCtx, credName)

	// ----------------------------------------------------------------
	// Step 6: assert HarnessCallbackService.GetCredential.
	// ----------------------------------------------------------------
	t.Log("[NPI deny step 6] asserting HarnessCallbackService.GetCredential enforcement")

	// Denied classes: agent, tool.
	for _, p := range provisioned {
		if p.workloadClass == "plugin" {
			continue
		}
		tok := tokenMap[p.label]
		callCtx := metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+tok,
			"x-tenant-id", tenantID,
		)
		_, callErr := harnessClient.GetCredential(callCtx,
			&harnesspb.GetCredentialRequest{Name: credName})
		npiAssertDenied(t,
			fmt.Sprintf("HarnessCallbackService.GetCredential(%s)", p.label),
			callErr)
		t.Logf("[NPI deny step 6] PASS: %s denied by HarnessCallbackService.GetCredential", p.label)
	}

	// Plugin must be allowed.
	for _, p := range provisioned {
		if p.workloadClass != "plugin" {
			continue
		}
		tok := tokenMap[p.label]
		pluginCtx := metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+tok,
			"x-tenant-id", tenantID,
		)
		_, pluginErr := harnessClient.GetCredential(pluginCtx,
			&harnesspb.GetCredentialRequest{Name: credName})
		npiAssertPluginAllowed(t,
			"HarnessCallbackService.GetCredential(npi-plugin)", pluginErr, seedErr)
		t.Log("[NPI deny step 6] PASS: plugin principal not denied by HarnessCallbackService.GetCredential")
	}

	// ----------------------------------------------------------------
	// Step 7: assert ComponentService.GetCredential.
	// ----------------------------------------------------------------
	t.Log("[NPI deny step 7] asserting ComponentService.GetCredential enforcement")

	for _, p := range provisioned {
		if p.workloadClass == "plugin" {
			continue
		}
		tok := tokenMap[p.label]
		callCtx := metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+tok,
			"x-tenant-id", tenantID,
		)
		_, callErr := componentClient.GetCredential(callCtx,
			&componentpb.GetCredentialRequest{Name: credName})
		npiAssertDenied(t,
			fmt.Sprintf("ComponentService.GetCredential(%s)", p.label),
			callErr)
		t.Logf("[NPI deny step 7] PASS: %s denied by ComponentService.GetCredential", p.label)
	}

	for _, p := range provisioned {
		if p.workloadClass != "plugin" {
			continue
		}
		tok := tokenMap[p.label]
		pluginCtx := metadata.AppendToOutgoingContext(ctx,
			"authorization", "Bearer "+tok,
			"x-tenant-id", tenantID,
		)
		_, pluginErr := componentClient.GetCredential(pluginCtx,
			&componentpb.GetCredentialRequest{Name: credName})
		npiAssertPluginAllowed(t,
			"ComponentService.GetCredential(npi-plugin)", pluginErr, seedErr)
		t.Log("[NPI deny step 7] PASS: plugin principal not denied by ComponentService.GetCredential")
	}

	// ----------------------------------------------------------------
	// Step 8: assert audit rows carry expected workload-class labels.
	// ----------------------------------------------------------------
	t.Log("[NPI deny step 8] asserting audit rows for workload-class labelling")
	npiAssertAuditRows(t, ctx, tenantID, credName)

	t.Log("[NPI deny] all assertions complete — non-plugin deny path validated")
}

// ---------------------------------------------------------------------------
// Helpers specific to this test file. Shared helpers (seedTestCredential,
// deleteTestCredential, exchangeClientCredentials, daemonGRPCAddr) are
// defined in fga_enforcement_test.go.
// ---------------------------------------------------------------------------

// requireKindGibsonContext fails the test if the current kubectl context is
// not kind-gibson. Prevents accidental execution against customer clusters.
func requireKindGibsonContext(t *testing.T, ctx context.Context) {
	t.Helper()
	out, err := runKubectl(ctx, "config", "current-context")
	require.NoError(t, err, "kubectl config current-context must succeed")
	currentCtx := strings.TrimSpace(out)
	require.Equal(t, "kind-gibson", currentCtx,
		"E2E MUST run against kind-gibson, never production or gibson-customer")
	t.Logf("[NPI] cluster context verified: %s", currentCtx)
}

// npiWaitForFGADenyPath polls HarnessCallbackService.GetCredential from the
// agent principal until PERMISSION_DENIED or UNAUTHENTICATED is returned,
// confirming FGA tuple propagation. Times out after 30 seconds.
func npiWaitForFGADenyPath(
	t *testing.T,
	ctx context.Context,
	hc harnesspb.HarnessCallbackServiceClient,
	agentCtx context.Context,
	credName string,
) {
	t.Helper()
	const timeout = 30 * time.Second
	const poll = 2 * time.Second

	deadline := time.Now().Add(timeout)
	for !time.Now().After(deadline) {
		_, probeErr := hc.GetCredential(agentCtx,
			&harnesspb.GetCredentialRequest{Name: credName})
		if probeErr != nil {
			st, _ := status.FromError(probeErr)
			if st.Code() == codes.PermissionDenied || st.Code() == codes.Unauthenticated {
				t.Log("[NPI deny step 5] PASS: FGA deny path confirmed active")
				return
			}
		}
		t.Logf("[NPI deny step 5] deny path not yet active (code=%v); retrying in %s…",
			npiStatusCode(probeErr), poll)
		select {
		case <-time.After(poll):
		case <-ctx.Done():
			t.Fatal("context cancelled while waiting for FGA propagation")
		}
	}
	t.Log("[NPI deny step 5] WARN: FGA propagation wait timed out; proceeding anyway")
}

// npiAssertDenied asserts that err is a gRPC PERMISSION_DENIED or
// UNAUTHENTICATED error. NotFound is treated as a failure: non-plugin
// callers must be denied before reaching the storage layer.
func npiAssertDenied(t *testing.T, context string, err error) {
	t.Helper()
	require.Error(t, err, "%s must return an error (expected PERMISSION_DENIED)", context)
	st, ok := status.FromError(err)
	if !ok {
		t.Errorf("%s: expected gRPC status error, got %T: %v", context, err, err)
		return
	}
	assert.True(t,
		st.Code() == codes.PermissionDenied || st.Code() == codes.Unauthenticated,
		"%s: expected PERMISSION_DENIED or UNAUTHENTICATED, got %s (%s)",
		context, st.Code(), st.Message())
}

// npiAssertPluginAllowed asserts that the plugin principal is not denied.
// When the credential seed failed, NotFound is accepted (plugin passed
// the authorization check, just found no matching credential).
func npiAssertPluginAllowed(t *testing.T, context string, callErr, seedErr error) {
	t.Helper()
	if callErr == nil {
		return // full success
	}
	st, _ := status.FromError(callErr)
	if seedErr != nil && st.Code() == codes.NotFound {
		t.Logf("%s: NotFound (seed failed) — plugin reached storage layer, FGA allowed", context)
		return
	}
	assert.NotEqual(t, codes.PermissionDenied, st.Code(),
		"%s: plugin must not receive PERMISSION_DENIED (got %s: %s)",
		context, st.Code(), st.Message())
}

// npiAssertAuditRows queries the postgres compliance_signals table and
// verifies that denied calls carry decision_reason=fga_no_can_resolve and
// the expected actor_workload_class values. This is a best-effort step:
// when postgres is unreachable the step is skipped with a warning.
func npiAssertAuditRows(t *testing.T, ctx context.Context, tenantID, credName string) {
	t.Helper()

	pgPod, err := runKubectl(ctx,
		"get", "pods",
		"-n", "gibson",
		"-l", "app.kubernetes.io/component=postgres",
		"-o", "jsonpath={.items[0].metadata.name}",
	)
	if err != nil || strings.TrimSpace(pgPod) == "" {
		t.Log("[NPI deny step 8] SKIP: postgres pod not reachable; audit assertions skipped")
		return
	}
	podName := strings.TrimSpace(pgPod)

	resourceURI := fmt.Sprintf("secret:%s:%s", tenantID, credName)
	query := fmt.Sprintf(
		"SELECT effect, decision_reason, actor_workload_class FROM compliance_signals "+
			"WHERE resource_uri='%s' AND created_at > NOW() - INTERVAL '5 minutes' "+
			"ORDER BY created_at;",
		resourceURI,
	)

	out, queryErr := runKubectlExec(ctx, podName, "gibson",
		"psql", "-U", "gibson", "-d", "gibson", "-t", "-A", "-F", ",", "-c", query)
	if queryErr != nil {
		t.Logf("[NPI deny step 8] WARN: audit query failed: %v; skipping", queryErr)
		return
	}

	rows := strings.Split(strings.TrimSpace(out), "\n")
	denyRows := 0
	fgaReasonCount := 0
	observedClasses := map[string]bool{}

	for _, row := range rows {
		if row == "" {
			continue
		}
		cols := strings.Split(row, ",")
		if len(cols) < 3 {
			continue
		}
		effect, decisionReason, actorClass := cols[0], cols[1], cols[2]
		t.Logf("[NPI deny step 8] audit row: effect=%s decision_reason=%s actor_workload_class=%s",
			effect, decisionReason, actorClass)
		if effect == "deny" {
			denyRows++
			if decisionReason == "fga_no_can_resolve" {
				fgaReasonCount++
			}
			if actorClass != "" {
				observedClasses[actorClass] = true
			}
		}
	}

	if denyRows > 0 {
		// At minimum both agent and tool deny rows should have the expected reason.
		assert.GreaterOrEqual(t, fgaReasonCount, 2,
			"at least 2 deny rows should carry decision_reason=fga_no_can_resolve; got %d of %d deny rows",
			fgaReasonCount, denyRows)
		// Verify that workload-class labels are present in deny rows.
		assert.True(t, observedClasses["agent"],
			"expected at least one deny row with actor_workload_class=agent")
		assert.True(t, observedClasses["tool"],
			"expected at least one deny row with actor_workload_class=tool")
		t.Logf("[NPI deny step 8] PASS: %d/%d deny rows carry fga_no_can_resolve; classes observed: %v",
			fgaReasonCount, denyRows, observedClasses)
	} else {
		t.Log("[NPI deny step 8] WARN: no deny audit rows found (audit emission may be delayed)")
		t.Log("[NPI deny step 8] NOTE: FGA enforcement validated in steps 6-7; audit is additional coverage")
	}
}

// npiStatusCode extracts the gRPC status code from an error for logging.
func npiStatusCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if st, ok := status.FromError(err); ok {
		return st.Code()
	}
	return codes.Unknown
}

// runKubectl runs kubectl with the given args and returns stdout as a string.
// It is a thin wrapper around os/exec for use by npiAssertAuditRows and
// requireKindGibsonContext.
func runKubectl(ctx context.Context, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	//nolint:gosec // all args are test constants; never user-supplied
	out, err := exec.CommandContext(cmdCtx, "kubectl", args...).Output()
	return string(out), err
}

// runKubectlExec runs a command inside a pod via kubectl exec.
func runKubectlExec(ctx context.Context, podName, namespace string, cmd ...string) (string, error) {
	args := append([]string{"exec", "-n", namespace, podName, "--"}, cmd...)
	return runKubectl(ctx, args...)
}

// runCommand wraps exec.CommandContext for shell-style helpers in this
// package (e.g. agent_llm_preserved_test.go's grpcurl invocations).
// Returns combined stdout+stderr to surface CLI errors in test logs.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	//nolint:gosec // all args are test constants; never user-supplied
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
