// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e — plugin_secret_revocation_test.go is the exit test for the
// plugin event stream (gibson#154, sdk#55).
//
// In plain words: when a tenant admin revokes a secret from a running
// plugin, the plugin knows within seconds and says so, instead of working
// with the revoked secret until its next restart.
//
// The proof on a live kind cluster:
//
//  1. The GitHub plugin image (ghcr.io/zeroroot-ai/integrations/github)
//     runs beside Envoy the way a customer deploys it: chart-rendered pod,
//     SPIFFE-SVID enrolment, cred:github_token declared as a required
//     startup secret. It reaches the daemon through Envoy and ext-authz,
//     never through the mTLS listener this suite dials.
//  2. This suite seeds cred:github_token, waits for the install to report
//     SERVING, and reads the binding the plugin wrote for itself
//     (bindDeclaredSecrets, ADR-0066).
//  3. Negative arm: with nothing revoked, the status holds SERVING for the
//     whole assertion window.
//  4. RevokePluginSecretBinding. The daemon publishes secret_access_revoked
//     on the plugin's WatchComponentEvents stream; the SDK marks the secret
//     revoked and turns Degraded; its next heartbeat carries that status;
//     ListPluginInstalls reports DEGRADED. The window is one heartbeat
//     interval (the daemon hands it out at registration) plus the stream's
//     latency plus a margin. A failure prints every poll.
//
// Per ADR-0012 this runs on `main` and on a schedule, never on a PR. The
// workflow is .github/workflows/exit-test-tool-dispatch.yml: the cluster
// it stands up has Envoy, Zitadel, SPIRE and the test-mode daemon, and the
// plugin is patched into the Argo application before this suite runs.
//
// Invocation (in-cluster, from the exit-test Job):
//
//	e2e.test -test.run TestPluginSecretRevocation -test.v -test.timeout 20m
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pluginadminv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
)

const (
	// revocationPluginName is the plugin's manifest metadata.name
	// (integrations/plugins/github/plugin.yaml) and the vendor key the
	// chart renders it under (plugins.github).
	revocationPluginName = "github"

	// revocationSecretName is the caller-facing name; SetSecret stores it
	// under the category prefix as revocationDeclaredName, which is the
	// exact ref the manifest declares (secrets[0].name).
	revocationSecretName   = "github_token"
	revocationDeclaredName = "cred:github_token"

	// revocationTenant is the install tenant the SVID-enrolled plugin binds
	// to: the daemon's GIBSON_PLATFORM_TENANT, "primary" on the baseline
	// profile (charts values-baseline.yaml).
	revocationTenant = "primary"

	// pluginReadyBudget bounds the wait for the plugin to enrol, resolve
	// its startup secret and heartbeat. The pod restarts on a back-off
	// while the secret is absent, and the secret lands seconds after this
	// suite starts, so a few minutes covers the worst back-off.
	pluginReadyBudget = 10 * time.Minute
	pluginReadyPoll   = 5 * time.Second

	// streamLatencyBudget is the time allowed for the revocation to travel
	// daemon -> Redis pub/sub -> hub -> the plugin's stream, and for the
	// plugin to act on it. Measured in milliseconds; five seconds is the
	// budget, not the expectation.
	streamLatencyBudget = 5 * time.Second

	// assertionMargin absorbs Envoy, ext-authz and the poll period.
	assertionMargin = 15 * time.Second

	statusPoll = time.Second
)

// revocationWindow is the time a revoked secret has to show as DEGRADED:
// the plugin reports its state on its next heartbeat, so one full interval
// is the worst case before the daemon can know.
var revocationWindow = component.HeartbeatInterval + streamLatencyBudget + assertionMargin

// TestPluginSecretRevocation is the gibson#154 exit test.
func TestPluginSecretRevocation(t *testing.T) {
	checkTestFixturesEnabled(t)

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })

	plugins := pluginadminv1.NewPluginAdminServiceClient(clients.Conn())
	secretsAdmin := tenantv1.NewSecretsServiceClient(clients.Conn())
	ctx := auth.ContextWithTenantString(context.Background(), revocationTenant)

	// The plugin declares cred:github_token as a required startup secret:
	// plugin.Serve refuses to start until it resolves. Seed it first, so the
	// pod the workflow already deployed comes up on its next restart.
	t.Run("the declared secret exists for the tenant", func(t *testing.T) {
		_, err := secretsAdmin.SetSecret(ctx, &tenantv1.SetSecretRequest{
			Name:     revocationSecretName,
			Category: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
			Value:    []byte("ghp_e2e_not_a_real_token"),
		})
		require.NoError(t, err, "SetSecret(%s) for %q", revocationDeclaredName, revocationTenant)
	})
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = secretsAdmin.DeleteSecret(auth.ContextWithTenantString(c, revocationTenant),
			&tenantv1.DeleteSecretRequest{Name: revocationDeclaredName})
	})

	var install *pluginadminv1.PluginInstallSummary
	t.Run("the plugin install reports serving and holds its declared binding", func(t *testing.T) {
		waitCtx, cancel := context.WithTimeout(ctx, pluginReadyBudget+time.Minute)
		defer cancel()
		deadline := time.Now().Add(pluginReadyBudget)
		// Registration writes SERVING before the plugin resolves its startup
		// secret, and a plugin that then dies leaves that status behind for
		// the 90-second TTL (run 35635251315). SERVING counts only once a
		// heartbeat moved past the registration time; a plugin that dies and
		// re-registers gets a new install id, so the search starts over.
		var history []helpers.PluginInstallObservation
		for install == nil {
			got, h, err := helpers.WaitForPluginInstallStatus(waitCtx, plugins, revocationPluginName, "",
				pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING, time.Until(deadline), pluginReadyPoll)
			history = append(history, h...)
			require.NoError(t, err, "the %s plugin never reported SERVING; every poll:\n%s", revocationPluginName, helpers.FormatObservations(history))
			alive, h, err := helpers.WaitForPluginInstallHeartbeat(waitCtx, plugins, revocationPluginName, got.GetInstallId(),
				got.GetLastHeartbeatAtUnix(), 2*component.HeartbeatInterval+assertionMargin, statusPoll)
			history = append(history, h...)
			if err != nil {
				require.False(t, time.Now().After(deadline),
					"no %s install stayed alive long enough to heartbeat within %s; every poll:\n%s",
					revocationPluginName, pluginReadyBudget, helpers.FormatObservations(history))
				t.Logf("install %s registered but never heartbeated (%v); looking for a live one", got.GetInstallId(), err)
				continue
			}
			install = alive
		}
		// The binding the revocation deletes is the one the plugin wrote for
		// itself at registration. Without it there is nothing to revoke and
		// the plugin could not have resolved its startup secret.
		require.Contains(t, install.GetBoundSecretRefs(), revocationDeclaredName,
			"install %s must hold can_resolve on its declared secret (bindDeclaredSecrets); got %v",
			install.GetInstallId(), install.GetBoundSecretRefs())
		t.Logf("plugin install %s is serving and heartbeating after %d polls", install.GetInstallId(), len(history))
	})

	// -----------------------------------------------------------------------
	// Negative arm: nothing revoked, the status holds for the same window
	// the positive arm gets. A status that flips on its own would make the
	// positive assertion vacuous.
	// -----------------------------------------------------------------------
	t.Run("the status stays serving while nothing is revoked", func(t *testing.T) {
		require.NotNil(t, install, "no serving install to observe")
		history, err := helpers.HoldPluginInstallStatus(ctx, plugins, revocationPluginName, install.GetInstallId(),
			pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_SERVING, revocationWindow, statusPoll)
		require.NoError(t, err, "the status must hold SERVING for %s with nothing revoked; every poll:\n%s",
			revocationWindow, helpers.FormatObservations(history))
	})

	// -----------------------------------------------------------------------
	// The assertion: revoke, then DEGRADED within one heartbeat plus the
	// stream latency plus the margin.
	// -----------------------------------------------------------------------
	t.Run("a revoked secret marks the plugin degraded within one heartbeat plus the stream latency", func(t *testing.T) {
		require.NotNil(t, install, "no serving install to revoke from")
		revokedAt := time.Now()
		_, err := plugins.RevokePluginSecretBinding(ctx, &pluginadminv1.RevokePluginSecretBindingRequest{
			InstallId:    install.GetInstallId(),
			DeclaredName: revocationDeclaredName,
		})
		require.NoError(t, err, "RevokePluginSecretBinding(%s, %s)", install.GetInstallId(), revocationDeclaredName)

		got, history, err := helpers.WaitForPluginInstallStatus(ctx, plugins, revocationPluginName, install.GetInstallId(),
			pluginadminv1.PluginInstallStatus_PLUGIN_INSTALL_STATUS_DEGRADED, revocationWindow, statusPoll)
		require.NoError(t, err,
			"install %s did not report DEGRADED within %s of the revocation (heartbeat %s + stream %s + margin %s); every poll:\n%s",
			install.GetInstallId(), revocationWindow, component.HeartbeatInterval, streamLatencyBudget, assertionMargin,
			helpers.FormatObservations(history))
		t.Logf("plugin install %s reported DEGRADED %s after the revocation (%d polls)",
			got.GetInstallId(), time.Since(revokedAt).Round(time.Millisecond), len(history))
	})
}
