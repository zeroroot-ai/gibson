// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/outsideagentstore"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// tenantOutsideStore holds outside agents by tenant. It is the store of the operator RPC tests.
type tenantOutsideStore struct {
	byTenant map[string][]outsideagentstore.Entry
	err      error
}

func (m *tenantOutsideStore) Register(context.Context, string, outsideagentstore.Entry) (*outsideagentstore.Entry, error) {
	return nil, errors.New("not used")
}

func (m *tenantOutsideStore) List(_ context.Context, tenant string) ([]outsideagentstore.Entry, error) {
	return m.byTenant[tenant], m.err
}

func (m *tenantOutsideStore) Get(_ context.Context, tenant, name string) (*outsideagentstore.Entry, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, e := range m.byTenant[tenant] {
		if e.Name == name {
			return &e, nil
		}
	}
	return nil, outsideagentstore.ErrNotFound
}

func (m *tenantOutsideStore) Delete(context.Context, string, string) error {
	return errors.New("not used")
}

func outsideOperatorServer(store outsideagentstore.Store, secrets ConnectorSecretResolver) *DaemonServer {
	srv := newPendingServer().WithModelProviderCredentialSource(secrets, testTenantOperatorSVID)
	return srv.WithOutsideAgentOperatorSource(store)
}

func TestGetTenantOutsideAgents_ReturnsTheRecordsOfOneTenant(t *testing.T) {
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme":  {{Name: "scout", A2AURL: "https://a.example/a2a", CredentialSecret: "scout-key"}},
		"other": {{Name: "intruder", A2AURL: "https://b.example"}},
	}}
	resp, err := outsideOperatorServer(store, &fakeCredStore{}).GetTenantOutsideAgents(
		peerCtx(t, testTenantOperatorSVID), &daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("GetTenantOutsideAgents: %v", err)
	}
	if len(resp.GetAgents()) != 1 {
		t.Fatalf("agents = %d, want 1", len(resp.GetAgents()))
	}
	a := resp.GetAgents()[0]
	if a.GetName() != "scout" || a.GetA2AUrl() != "https://a.example/a2a" || a.GetCredentialSecret() != "scout-key" {
		t.Errorf("agent = %v", a)
	}
}

func TestGetTenantOutsideAgents_StoreErrorIsAnError(t *testing.T) {
	store := &tenantOutsideStore{err: errors.New("db down")}
	_, err := outsideOperatorServer(store, &fakeCredStore{}).GetTenantOutsideAgents(
		peerCtx(t, testTenantOperatorSVID), &daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

func TestGetOutsideAgentCredential_ReturnsTheAuthorizationKey(t *testing.T) {
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {{Name: "scout", CredentialSecret: "scout-key"}},
	}}
	secrets := &fakeCredStore{data: map[string][]byte{"cred:scout-key": []byte("tok-1")}}
	resp, err := outsideOperatorServer(store, secrets).GetOutsideAgentCredential(
		peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: "scout"})
	if err != nil {
		t.Fatalf("GetOutsideAgentCredential: %v", err)
	}
	if got := string(resp.GetData()[OutsideAgentCredentialKey]); got != "tok-1" || len(resp.GetData()) != 1 {
		t.Errorf("data = %v", resp.GetData())
	}
	if len(secrets.tenants) != 1 || secrets.tenants[0] != "acme" {
		t.Errorf("the read used the tenants %v, want [acme]", secrets.tenants)
	}
}

func TestGetOutsideAgentCredential_NotFound(t *testing.T) {
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {{Name: "open"}, {Name: "scout", CredentialSecret: "missing"}},
	}}
	cases := map[string]string{
		"no record":            "ghost",
		"no credential secret": "open",
		"secret missing":       "scout",
	}
	for name, agent := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := outsideOperatorServer(store, &fakeCredStore{}).GetOutsideAgentCredential(
				peerCtx(t, testTenantOperatorSVID),
				&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: agent})
			if status.Code(err) != codes.NotFound {
				t.Fatalf("code = %v, want NotFound", status.Code(err))
			}
		})
	}
}

func TestGetOutsideAgentCredential_OtherTenantRecordIsNotFound(t *testing.T) {
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"other": {{Name: "scout", CredentialSecret: "scout-key"}},
	}}
	secrets := &fakeCredStore{data: map[string][]byte{"cred:scout-key": []byte("tok")}}
	_, err := outsideOperatorServer(store, secrets).GetOutsideAgentCredential(
		peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: "scout"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestOutsideAgentOperatorRPCs_OnlyTheTenantOperator(t *testing.T) {
	store := &tenantOutsideStore{byTenant: map[string][]outsideagentstore.Entry{
		"acme": {{Name: "scout", CredentialSecret: "scout-key"}},
	}}
	secrets := &fakeCredStore{data: map[string][]byte{"cred:scout-key": []byte("tok")}}
	srv := outsideOperatorServer(store, secrets)
	callers := map[string]context.Context{
		"the connector operator": peerCtx(t, testConnectorOperatorSVID),
		"the edge":               peerCtx(t, testEdgeSVID),
		"no peer":                context.Background(),
	}
	for name, ctx := range callers {
		t.Run(name, func(t *testing.T) {
			_, err := srv.GetTenantOutsideAgents(ctx, &daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme"})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("GetTenantOutsideAgents code = %v, want PermissionDenied", status.Code(err))
			}
			_, err = srv.GetOutsideAgentCredential(ctx,
				&daemonoperatorv1.GetOutsideAgentCredentialRequest{TenantId: "acme", Name: "scout"})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("GetOutsideAgentCredential code = %v, want PermissionDenied", status.Code(err))
			}
		})
	}
	if len(secrets.tenants) != 0 {
		t.Errorf("a refused caller reached the secret store: %v", secrets.tenants)
	}
}

func TestOutsideAgentOperatorRPCs_UnwiredIsUnavailable(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.GetTenantOutsideAgents(peerCtx(t, testTenantOperatorSVID),
		&daemonoperatorv1.GetTenantOutsideAgentsRequest{TenantId: "acme"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}
