// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// aapLikeEntry is a Hosted connector that needs the address of a host of the
// customer (gibson#1508).
func aapLikeEntry() componentcatalog.ConnectorEntry {
	return componentcatalog.ConnectorEntry{
		ID:          "aap-like",
		Shape:       connectorv1alpha1.ConnectorShapeHosted,
		Image:       "registry.example.com/aap/mcp@sha256:abc",
		EgressAllow: []string{"registry-static.example.com:443"},
		Env:         map[string]string{"ALLOW_WRITE_OPERATIONS": "false"},
		Variables: []componentcatalog.TenantVariable{
			{Name: "base_url", Env: "BASE_URL", Kind: componentcatalog.VariableKindEndpoint, Patterns: []string{
				"https://aap.corp-example.com", "https://aap.corp-example.com:8443",
			}},
		},
	}
}

func TestTenantChoice_HostedVariables(t *testing.T) {
	entry := aapLikeEntry()
	cfg, err := tenantChoice(entry, &tenantv1.EnableConnectorRequest{
		CatalogId: "aap-like", Variables: map[string]string{"base_url": "https://aap.corp-example.com/"}})
	require.NoError(t, err)
	assert.Equal(t, "https://aap.corp-example.com/", cfg.Variables["base_url"])

	for name, vars := range map[string]map[string]string{
		"missing":         nil,
		"private address": {"base_url": "https://10.1.2.3/"},
		"cluster service": {"base_url": "https://gibson-daemon.gibson.svc.cluster.local/"},
		"undeclared":      {"base_url": "https://aap.corp-example.com/", "other": "https://x.example.com/"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tenantChoice(entry, &tenantv1.EnableConnectorRequest{CatalogId: "aap-like", Variables: vars})
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
		})
	}

	// An entry that declares no variable takes none.
	plain := componentcatalog.ConnectorEntry{ID: "p", Shape: connectorv1alpha1.ConnectorShapeHosted}
	_, err = tenantChoice(plain, &tenantv1.EnableConnectorRequest{CatalogId: "p",
		Variables: map[string]string{"base_url": "https://aap.corp-example.com/"}})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

// The pod gets the value as a variable, and the egress allow-list follows it.
// A stored value that breaks the rules of a later manifest reaches no host.
func TestDesiredConnector_HostedEgressFollowsTheVariable(t *testing.T) {
	srv := newPendingServer()
	entry := aapLikeEntry()

	good, err := srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: "aap-like",
		Config: tenantconnector.Config{Variables: map[string]string{"base_url": "https://aap.corp-example.com:8443/"}}}, entry)
	require.NoError(t, err)
	assert.Equal(t, "https://aap.corp-example.com:8443/", good.GetEnv()["BASE_URL"])
	assert.Equal(t, "false", good.GetEnv()["ALLOW_WRITE_OPERATIONS"])
	assert.True(t, slices.Contains(good.GetEgressAllow(), "aap.corp-example.com:8443"), "%v", good.GetEgressAllow())
	assert.True(t, slices.Contains(good.GetEgressAllow(), "registry-static.example.com:443"), "%v", good.GetEgressAllow())
	assert.Empty(t, entry.Env["BASE_URL"], "the catalog entry must not change")

	// A stored value that the rules refuse fails loudly: no desired connector
	// (review M10).
	bad, err := srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: "aap-like",
		Config: tenantconnector.Config{Variables: map[string]string{"base_url": "https://10.0.0.5/"}}}, entry)
	require.Error(t, err)
	assert.Nil(t, bad)
}

// A variable with a default takes it when the tenant gives none, so the egress
// list holds the host that the server calls by default (review M10).
func TestDesiredConnector_AVariableWithADefault(t *testing.T) {
	srv := newPendingServer()
	for id, want := range map[string]string{
		"github-fixloop":             "api.github.com:443",
		"crowdstrike-response":       "api.crowdstrike.com:443",
		"defender-endpoint-response": "api.security.microsoft.com:443",
	} {
		entry, err := componentcatalog.LookupConnector(id)
		require.NoError(t, err)
		d, err := srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: id}, entry)
		require.NoError(t, err, id)
		assert.True(t, slices.Contains(d.GetEgressAllow(), want), "%s egress = %v", id, d.GetEgressAllow())
	}
}

// The tenant names a secret of its own that holds a CA bundle. The daemon
// hands the name to the operator, and refuses a name outside the prefix of the
// connector (gibson#1517).
func TestDesiredConnector_CABundleReachesTheOperator(t *testing.T) {
	srv := newPendingServer()
	entry := aapLikeEntry()
	entry.Variables = append(entry.Variables, componentcatalog.TenantVariable{Name: "ca_bundle", Kind: componentcatalog.VariableKindCABundle})
	base := map[string]string{"base_url": "https://aap.corp-example.com/"}

	cfg, err := tenantChoice(entry, &tenantv1.EnableConnectorRequest{CatalogId: "aap-like",
		Variables: map[string]string{"base_url": base["base_url"], "ca_bundle": "aap-like-ca-corp"}})
	require.NoError(t, err)
	d, err := srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: "aap-like", Config: cfg}, entry)
	require.NoError(t, err)
	assert.Equal(t, "aap-like-ca-corp", d.GetCaBundleSecret())
	assert.NotContains(t, d.GetEnv(), "ca_bundle")

	// No bundle: the field stays empty and the connector is unchanged.
	d, err = srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: "aap-like",
		Config: tenantconnector.Config{Variables: base}}, entry)
	require.NoError(t, err)
	assert.Empty(t, d.GetCaBundleSecret())

	// Another secret of the tenant is refused at enable time and at hand-over.
	_, err = tenantChoice(entry, &tenantv1.EnableConnectorRequest{CatalogId: "aap-like",
		Variables: map[string]string{"base_url": base["base_url"], "ca_bundle": "aap-like-token"}})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	bad, err := srv.desiredConnector(tenantconnector.Connector{TenantID: "acme", ConnectorID: "aap-like",
		Config: tenantconnector.Config{Variables: map[string]string{"base_url": base["base_url"], "ca_bundle": "aap-like-token"}}}, entry)
	require.Error(t, err)
	assert.Nil(t, bad)
}

// The operator asks for the CA bundle with the key "ca.crt". The daemon reads
// the secret under the name as given, the way it reads the credentials of the
// same connector, and it returns the certificates only (gibson#1517).
func TestGetConnectorCredential_ReadsTheCABundleOfTheTenant(t *testing.T) {
	bundle := testCABundle(t)
	srv := credServer(&fakeCredStore{data: map[string][]byte{
		"github-fixloop-ca-mock":          bundle,
		"github-fixloop-ca-key":           []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
		"github-fixloop-ca-token":         append([]byte("ghp_secrettoken\n"), bundle...),
		"github-fixloop-token":            []byte("tok"),
		"cred:github-fixloop-ca-prefixed": bundle, // a different rule: not read
	}})
	get := func(name string) (*daemonoperatorv1.GetConnectorCredentialResponse, error) {
		return srv.GetConnectorCredential(peerCtx(t, testConnectorOperatorSVID), &daemonoperatorv1.GetConnectorCredentialRequest{
			TenantId: "acme", ConnectorId: "github-fixloop",
			Credentials: []*daemonoperatorv1.ConnectorCredentialRef{
				{Key: "github-fixloop-token", TargetEnv: "GITHUB_TOKEN"},
				{Key: name, TargetEnv: "ca.crt"},
			},
		})
	}

	resp, err := get("github-fixloop-ca-mock")
	require.NoError(t, err)
	assert.Equal(t, bundle, resp.GetData()["ca.crt"])
	assert.Equal(t, "tok", string(resp.GetData()["GITHUB_TOKEN"]))

	for _, name := range []string{"github-fixloop-ca-key", "github-fixloop-ca-token", "github-fixloop-ca-prefixed"} {
		_, err = get(name)
		require.Error(t, err, name)
		assert.NotContains(t, err.Error(), "AAAA")
		assert.NotContains(t, err.Error(), "ghp_secrettoken", "the error never holds the content")
	}
}

// EnableConnector reads the bundle at once. A missing secret, a secret that is
// not a CA bundle and a daemon with no secret store are refused (gibson#1517).
func TestEnableConnector_ChecksTheCABundleAtEnableTime(t *testing.T) {
	bundle := testCABundle(t)
	store := &fakeCredStore{data: map[string][]byte{
		"github-fixloop-ca-ok":  bundle,
		"github-fixloop-ca-bad": append([]byte("ghp_secrettoken\n"), bundle...),
	}}
	enable := func(svc *ConnectorService, name string) error {
		_, err := svc.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{
			CatalogId: "github-fixloop", Variables: map[string]string{"ca_bundle": name},
		})
		return err
	}

	s, rows := newConnectorService(t)
	s.WithSecretStore(store)
	assert.Equal(t, codes.InvalidArgument, grpcCode(enable(s, "github-fixloop-ca-missing")))
	assert.Equal(t, codes.InvalidArgument, grpcCode(enable(s, "github-fixloop-ca-bad")))
	assert.Equal(t, codes.InvalidArgument, grpcCode(enable(s, "github-fixloop-token")), "outside the prefix")
	assert.Empty(t, rows.rows, "a refused request leaves no row")
	require.NoError(t, enable(s, "github-fixloop-ca-ok"))
	require.Len(t, rows.rows, 1)

	noStore, _ := newConnectorService(t)
	assert.Equal(t, codes.FailedPrecondition, grpcCode(enable(noStore, "github-fixloop-ca-ok")))
}
