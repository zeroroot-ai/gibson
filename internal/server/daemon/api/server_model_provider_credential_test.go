// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func modelCredServer(store ConnectorSecretResolver) *DaemonServer {
	srv := newPendingServer()
	return srv.WithModelProviderCredentialSource(store, testTenantOperatorSVID)
}

func modelCredReq(typ, secret string) *daemonoperatorv1.GetModelProviderCredentialRequest {
	return &daemonoperatorv1.GetModelProviderCredentialRequest{
		TenantId: "acme", CredentialSecret: secret, ProviderType: typ,
	}
}

func TestGetModelProviderCredential_APIKey(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{"provider_cred:claude:api_key": []byte("sk-ant-secret")}}
	resp, err := modelCredServer(store).GetModelProviderCredential(
		peerCtx(t, testTenantOperatorSVID), modelCredReq("anthropic", "provider_cred:claude"))
	if err != nil {
		t.Fatalf("GetModelProviderCredential: %v", err)
	}
	if got := string(resp.GetSecret().GetData()[ModelCredentialKeyAuthorization]); got != "sk-ant-secret" {
		t.Errorf("Authorization = %q", got)
	}
	if len(resp.GetSecret().GetData()) != 1 {
		t.Errorf("keys = %d, want 1", len(resp.GetSecret().GetData()))
	}
	if len(store.tenants) != 1 || store.tenants[0] != "acme" {
		t.Errorf("the read used the tenants %v, want [acme]", store.tenants)
	}
}

func TestGetModelProviderCredential_Bedrock(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{
		"provider_cred:aws:aws_access_key_id":     []byte("AK"),
		"provider_cred:aws:aws_secret_access_key": []byte("SK"),
		"provider_cred:aws:aws_session_token":     []byte("ST"),
	}}
	resp, err := modelCredServer(store).GetModelProviderCredential(
		peerCtx(t, testTenantOperatorSVID), modelCredReq("bedrock", "provider_cred:aws"))
	if err != nil {
		t.Fatalf("GetModelProviderCredential: %v", err)
	}
	d := resp.GetSecret().GetData()
	if string(d["accessKey"]) != "AK" || string(d["secretKey"]) != "SK" || string(d["sessionToken"]) != "ST" {
		t.Errorf("data = %v", d)
	}
}

func TestModelCredentialFor_Refusals(t *testing.T) {
	cases := map[string]struct {
		typ  string
		data map[string][]byte
	}{
		"no api key":            {"openai", map[string][]byte{}},
		"empty api key":         {"openai", map[string][]byte{"provider_cred:p:api_key": {}}},
		"bedrock no secret key": {"bedrock", map[string][]byte{"provider_cred:p:aws_access_key_id": []byte("AK")}},
		"bedrock no access key": {"bedrock", map[string][]byte{"provider_cred:p:aws_secret_access_key": []byte("SK")}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := modelCredentialFor(context.Background(), &fakeCredStore{data: c.data}, c.typ, "provider_cred:p")
			if err == nil {
				t.Fatal("the credential was accepted")
			}
		})
	}
}

func TestGetModelProviderCredential_OnlyTheTenantOperator(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{"provider_cred:k:api_key": []byte("v")}}
	srv := modelCredServer(store)
	cases := map[string]context.Context{
		"the connector operator": peerCtx(t, testConnectorOperatorSVID),
		"the edge":               peerCtx(t, testEdgeSVID),
		"no SPIFFE ID":           peerCtx(t, ""),
		"no peer":                auth.WithTenant(context.Background(), mustTenant("acme")),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := srv.GetModelProviderCredential(ctx, modelCredReq("openai", "provider_cred:k"))
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err = %v, want PermissionDenied", err)
			}
		})
	}
	if len(store.tenants) != 0 {
		t.Errorf("the store was read %d times for a refused caller", len(store.tenants))
	}
}

func TestGetModelProviderCredential_Unwired(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), modelCredReq("openai", "provider_cred:k"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

func TestGetModelProviderCredential_MissingSecret(t *testing.T) {
	srv := modelCredServer(&fakeCredStore{data: map[string][]byte{}})
	_, err := srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), modelCredReq("openai", "provider_cred:k"))
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}

// fakeProviders is a provider record store with a fixed list.
type fakeProviders struct {
	providerConfigStoreIface
	records []*providerconfig.ProviderConfig
}

func (f fakeProviders) List(context.Context, string) ([]*providerconfig.ProviderConfig, error) {
	return f.records, nil
}

func TestGetTenantModelProviders(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{
		"provider_cred:eu:aws_region":          []byte("eu-west-1"),
		"provider_cred:local:base_url":         []byte("https://llm.internal"),
		"provider_cred:local:ca_bundle_secret": []byte("local-ca"),
		"provider_cred:claude:api_key":         []byte("sk-secret-do-not-return"),
		"provider_cred:vx:project_id":          []byte("proj"),
		"provider_cred:vx:region":              []byte("us-east5"),
	}}
	srv := modelCredServer(store)
	srv.providerConfig = fakeProviders{records: []*providerconfig.ProviderConfig{
		{Name: "claude", Type: providerconfig.ProviderAnthropic, Enabled: true},
		{Name: "eu", Type: providerconfig.ProviderBedrock, Enabled: true},
		{Name: "local", Type: providerconfig.ProviderOpenAICompatible, Enabled: true},
		{Name: "vx", Type: providerconfig.ProviderVertex, Enabled: true},
		{Name: "off", Type: providerconfig.ProviderOpenAI, Enabled: false},
		{Name: "emb", Type: providerconfig.ProviderVoyage, Enabled: true},
		{Name: "cf", Type: providerconfig.ProviderCloudflare, Enabled: true},
	}}
	resp, err := srv.GetTenantModelProviders(peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("GetTenantModelProviders: %v", err)
	}
	got := map[string]*daemonoperatorv1.DesiredModelProvider{}
	for _, p := range resp.GetProviders() {
		got[p.GetName()] = p
		if strings.Contains(p.String(), "sk-secret") {
			t.Errorf("the reply holds a credential value: %v", p)
		}
	}
	if len(got) != 4 {
		t.Fatalf("providers = %v, want claude, eu, local, vx", got)
	}
	if c := got["claude"]; c.GetType() != "anthropic" || c.GetCredentialSecret() != "provider_cred:claude" {
		t.Errorf("claude = %v", c)
	}
	if e := got["eu"]; e.GetType() != "bedrock" || e.GetRegion() != "eu-west-1" {
		t.Errorf("eu = %v", e)
	}
	if l := got["local"]; l.GetType() != "openai-compatible" || l.GetBaseUrl() != "https://llm.internal" ||
		l.GetCaBundleSecret() != "local-ca" {
		t.Errorf("local = %v", l)
	}
	if c := got["claude"]; c.GetCaBundleSecret() != "" {
		t.Errorf("claude has a CA bundle secret %q, want none", c.GetCaBundleSecret())
	}
	if v := got["vx"]; v.GetType() != "vertexai" || v.GetProjectId() != "proj" || v.GetRegion() != "us-east5" {
		t.Errorf("vx = %v", v)
	}
	if len(resp.GetSkipped()) != 2 {
		t.Fatalf("skipped = %v, want voyage and cloudflare", resp.GetSkipped())
	}
	if !strings.Contains(strings.Join(resp.GetSkipped(), "|"), "emb: voyage is not a provider type") {
		t.Errorf("skipped = %v", resp.GetSkipped())
	}
}

func TestGetTenantModelProviders_OnlyTheTenantOperator(t *testing.T) {
	srv := modelCredServer(&fakeCredStore{})
	srv.providerConfig = fakeProviders{}
	_, err := srv.GetTenantModelProviders(peerCtx(t, testConnectorOperatorSVID),
		&daemonoperatorv1.GetTenantModelProvidersRequest{TenantId: "acme"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}
