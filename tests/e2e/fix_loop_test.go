// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e: fix_loop_test.go is the exit test of the fix loop epic (gibson#1469).
//
// In plain words: a tenant enables the connector of its Git host and the connector
// of its metrics. Both run in the tenant namespace and call a mock forge over TLS.
// The mock is the zeroroot-ai/connectors image mock-forge. It runs outside the
// cluster, next to the kind nodes. The forge uses a private CA, so each connector
// needs the CA bundle that the tenant stores as a secret (gibson#1517).
//
// The test reads the daemon API only. It never writes a status, and it never writes
// to a database. The mock is the stand-in for the tools of the buyer, so the test
// seeds it and changes its health value through its control API, as the buyer's
// tools would change by themselves.
//
// What this file proves:
//
//	1  the connectors of the fix loop run with the CA bundle of the tenant     "both connectors run ..."
//	2  a governed connector call reaches the mock over TLS                      "a governed call of the git host ..."
//	3  the health signal of the tenant reads the metrics of the mock            "the health signal ..."
//
// What it does not prove yet: case 1 (the agent fixes the flaw, the signal holds,
// the finding is verified with an exposure window) and case 2 (the fix breaks the
// service, the daemon reverts it, the finding is open, and the revert rate counts
// it). Both need a finding that a scan mission raised on an Application, and no
// producer of that finding exists that a test can drive without a real scanner.
// See the report on gibson#1469.
//
// It needs GIBSON_TEST_FIXTURES_ENABLED=true, DAEMON_GRPC_ADDR, FIXLOOP_MOCK_URL and
// FIXLOOP_MOCK_CA_B64 (the PEM of the authority of the mock, in base64).
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	fixLoopTenant = "primary"
	fixLoopAgent  = "e2e-fixloop-agent"
	// The application key of the fixture. The git host connector returns
	// owner/repo as the application, and the tenant keys its health query by it.
	fixLoopOwner = "acme"
	fixLoopRepo  = "shop"
	fixLoopApp   = fixLoopOwner + "/" + fixLoopRepo
	// The second repository holds the fixture of case 2.
	fixLoopRepo2 = "shop2"
	fixLoopApp2  = fixLoopOwner + "/" + fixLoopRepo2

	fixLoopGitConnector     = "github-fixloop"
	fixLoopMetricsConnector = "prometheus-health"
	fixLoopConnectorsReady  = 10 * time.Minute
	fixLoopCallTimeout      = 6 * time.Minute
)

// mockForge is the control client of the mock forge. It trusts the authority of
// the mock and no other.
type mockForge struct {
	url  string
	http *http.Client
}

func newMockForge(t *testing.T) *mockForge {
	t.Helper()
	url := os.Getenv("FIXLOOP_MOCK_URL")
	require.NotEmpty(t, url, "FIXLOOP_MOCK_URL is not set: the workflow starts the mock forge and passes its URL")
	encoded := os.Getenv("FIXLOOP_MOCK_CA_B64")
	require.NotEmpty(t, encoded, "FIXLOOP_MOCK_CA_B64 is not set: the workflow passes the authority of the mock")
	ca, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err, "decode FIXLOOP_MOCK_CA_B64")
	client, err := helpers.HTTPClientWithCA(string(ca))
	require.NoError(t, err)
	return &mockForge{url: strings.TrimRight(url, "/"), http: client}
}

// call sends one JSON request to the mock and decodes the JSON answer. A status
// of 300 or more fails the test.
func (m *mockForge) call(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, m.url+path, rd)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.http.Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Less(t, resp.StatusCode, 300, "%s %s answered %d: %s", method, path, resp.StatusCode, raw)
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		require.NoError(t, json.Unmarshal(raw, &out), "decode the answer of %s %s: %s", method, path, raw)
	}
	return out
}

// seedFlawedRepository makes the repository of the fixture: one file with a known
// flaw, and an automatic deploy of each commit on the default branch. It returns
// the number of an open pull request from a branch that changes the file.
func (m *mockForge) seedFlawedRepository(t *testing.T) int {
	t.Helper()
	m.call(t, http.MethodPost, "/_mock/reset", nil)
	m.call(t, http.MethodPost, "/_mock/repos", map[string]any{
		"owner": fixLoopOwner, "repo": fixLoopRepo,
		"files": map[string]any{
			"src/db.go": "package db\n\n// FLAW: the query is built with string concatenation.\n",
		},
		"auto_deploy": map[string]any{"environment": "production", "state": "success"},
	})
	m.call(t, http.MethodPost, "/_mock/repos/"+fixLoopApp+"/commits", map[string]any{
		"branch": "fix/e2e", "message": "fix: use a bound parameter",
		"files": map[string]any{"src/db.go": "package db\n\n// The query uses a bound parameter.\n"},
	})
	pr := m.call(t, http.MethodPost, "/repos/"+fixLoopApp+"/pulls", map[string]any{
		"title": "Use a bound parameter", "head": "fix/e2e", "base": "main",
	})
	n, ok := pr["number"].(float64)
	require.True(t, ok, "the mock answered no pull request number: %v", pr)
	return int(n)
}

// setHealth sets the health value of the metrics of the mock from now on.
func (m *mockForge) setHealth(t *testing.T, value float64) {
	t.Helper()
	m.call(t, http.MethodPost, "/_mock/prometheus/health", map[string]any{"value": value})
}

// fixLoopSecrets stores the secrets of the two connectors in the tenant secret
// store, the way a tenant admin does with SetSecret. The others have no category, as the manifests name them.
// The CA bundle of a connector is stored like its credentials: with no category.
func fixLoopSecrets(ctx context.Context, t *testing.T, secrets secretsv1.SecretsServiceClient, ca []byte) (gitCA, metricsCA string) {
	t.Helper()
	gitCA = fixLoopGitConnector + "-ca-mock"
	metricsCA = fixLoopMetricsConnector + "-ca-mock"
	queries, err := json.Marshal(map[string]string{fixLoopApp: `up{job="shop"}`, fixLoopApp2: `up{job="shop2"}`})
	require.NoError(t, err)
	set := func(name string, cat secretsv1.SecretCategory, value []byte) {
		_, serr := secrets.SetSecret(ctx, &secretsv1.SetSecretRequest{Name: name, Category: cat, Value: value})
		require.NoError(t, serr, "SetSecret(%s)", name)
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), fixLoopTenant), 30*time.Second)
			defer cancel()
			_, _ = secrets.DeleteSecret(c, &secretsv1.DeleteSecretRequest{Name: name})
		})
	}
	set(gitCA, secretsv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, ca)
	set(metricsCA, secretsv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, ca)
	// The mock checks no credential. The values only have to exist.
	set("github-fixloop-token", secretsv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, []byte("mock-token"))
	set("prometheus-health-bearer-token", secretsv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, []byte("mock-token"))
	set("prometheus-health-queries", secretsv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, queries)
	return gitCA, metricsCA
}

// TestFixLoop is the exit test of gibson#1469. See the header for what it holds.
func TestFixLoop(t *testing.T) {
	checkTestFixturesEnabled(t)
	forge := newMockForge(t)
	ca, err := base64.StdEncoding.DecodeString(os.Getenv("FIXLOOP_MOCK_CA_B64"))
	require.NoError(t, err)

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })
	ctx := auth.ContextWithTenantString(context.Background(), fixLoopTenant)
	connectors := tenantv1.NewConnectorServiceClient(clients.Conn())
	secrets := secretsv1.NewSecretsServiceClient(clients.Conn())
	comp := componentpb.NewComponentServiceClient(clients.Conn())
	membership := tenantv1.NewMembershipServiceClient(clients.Conn())

	var mrNumber int
	t.Run("the mock forge answers over TLS and holds the flawed repository", func(t *testing.T) {
		mrNumber = forge.seedFlawedRepository(t)
		state := forge.call(t, http.MethodGet, "/_mock/repos/"+fixLoopApp, nil)
		require.NotEmpty(t, state, "the mock holds the repository")
	})

	gitCA, metricsCA := fixLoopSecrets(ctx, t, secrets, ca)
	mockURL := forge.url

	t.Run("both connectors run with the CA bundle of the tenant", func(t *testing.T) {
		enable := func(id string, vars map[string]string) {
			_, eerr := connectors.EnableConnector(ctx, &tenantv1.EnableConnectorRequest{CatalogId: id, Variables: vars})
			require.NoError(t, eerr, "EnableConnector(%s)", id)
			t.Cleanup(func() {
				c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), fixLoopTenant), 30*time.Second)
				defer cancel()
				_, _ = connectors.DisableConnector(c, &tenantv1.DisableConnectorRequest{Connector: id})
			})
		}
		enable(fixLoopGitConnector, map[string]string{"api_url": mockURL, "ca_bundle": gitCA})
		enable(fixLoopMetricsConnector, map[string]string{"base_url": mockURL, "ca_bundle": metricsCA})

		helpers.Eventually(t, fixLoopConnectorsReady, "both connectors report Ready", func() (bool, string) {
			resp, lerr := connectors.ListConnectors(ctx, &tenantv1.ListConnectorsRequest{})
			if lerr != nil {
				return false, lerr.Error()
			}
			phases := map[string]string{}
			for _, c := range resp.GetConnectors() {
				phases[c.GetId()] = c.GetPhase()
				if c.GetLastError() != "" {
					phases[c.GetId()] += " (" + c.GetLastError() + ")"
				}
			}
			ready := phases[fixLoopGitConnector] == "Ready" && phases[fixLoopMetricsConnector] == "Ready"
			return ready, fmt.Sprint(phases)
		})
	})

	targetID, err := helpers.RegisterTestTarget(ctx, clients.Daemon, toolTargetName, toolTargetURL)
	require.NoError(t, err, "register the synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), fixLoopTenant), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(c, clients.Daemon, targetID)
	})
	agent := helpers.StartHeldAgent(ctx, t, comp, membership, fixLoopAgent)
	defID := helpers.CreateAgentMission(ctx, t, clients.Daemon, "fix-loop-exit", fixLoopAgent, nil)
	run := helpers.StartMission(ctx, t, clients.Daemon, defID, targetID)
	work := agent.Next(t, fixLoopCallTimeout)

	// call makes one governed connector call and decodes the JSON object. It
	// returns an error and never fails a test, so a caller can retry.
	call := func(tool string, args map[string]any) (map[string]any, error) {
		raw, merr := json.Marshal(args)
		if merr != nil {
			return nil, merr
		}
		resp, cerr := comp.CallTool(ctx, &componentpb.CallToolRequest{
			WorkId: work.WorkID, ToolName: tool, InputJson: string(raw),
		})
		if cerr != nil {
			return nil, fmt.Errorf("CallTool(%s): %w", tool, cerr)
		}
		out := map[string]any{}
		if uerr := json.Unmarshal([]byte(resp.GetOutputJson()), &out); uerr != nil {
			return nil, fmt.Errorf("decode the result of %s: %s: %w", tool, resp.GetOutputJson(), uerr)
		}
		return out, nil
	}

	t.Run("a governed call of the git host reaches the mock over TLS", func(t *testing.T) {
		key := fmt.Sprintf("%s#%d", fixLoopApp, mrNumber)
		var got map[string]any
		helpers.Eventually(t, 3*time.Minute, "merge_request_state answers", func() (bool, string) {
			var cerr error
			got, cerr = call("mcp:"+fixLoopGitConnector+":merge_request_state", map[string]any{"merge_request": key})
			if cerr != nil {
				return false, cerr.Error()
			}
			return true, ""
		})
		require.Equal(t, "open", got["state"], "the pull request that the mock holds is open: %v", got)
		require.Equal(t, true, got["pipeline_green"], "the default check of the mock passed: %v", got)
	})

	t.Run("the health signal of the tenant reads the metrics of the mock", func(t *testing.T) {
		forge.setHealth(t, 1)
		var got map[string]any
		helpers.Eventually(t, 3*time.Minute, "health_signal answers", func() (bool, string) {
			var cerr error
			got, cerr = call("mcp:"+fixLoopMetricsConnector+":health_signal", map[string]any{
				"application": fixLoopApp, "since": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "hold_seconds": 60,
			})
			if cerr != nil {
				return false, cerr.Error()
			}
			return true, ""
		})
		require.Equal(t, true, got["known"], "the tenant stated a query for %s: %v", fixLoopApp, got)
	})

	runFixLoopCases(t, &fixLoopWorld{
		ctx: ctx, clients: clients, forge: forge, daemon: clients.Daemon,
		world: worldpb.NewWorldServiceClient(clients.Conn()), targetID: targetID, bankName: "fix-loop-bank",
	})

	work.Complete()
	require.Equal(t, "mission_completed", run.Wait(t, fixLoopCallTimeout).EventType, "the mission must complete")
}
