// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	store := &fakeCredStore{data: map[string][]byte{"anthropic-key": []byte("sk-ant-secret")}}
	resp, err := modelCredServer(store).GetModelProviderCredential(
		peerCtx(t, testTenantOperatorSVID), modelCredReq("anthropic", "anthropic-key"))
	if err != nil {
		t.Fatalf("GetModelProviderCredential: %v", err)
	}
	if got := string(resp.GetData()[ModelCredentialKeyAuthorization]); got != "sk-ant-secret" {
		t.Errorf("Authorization = %q", got)
	}
	if len(resp.GetData()) != 1 {
		t.Errorf("keys = %d, want 1", len(resp.GetData()))
	}
	if len(store.tenants) != 1 || store.tenants[0] != "acme" {
		t.Errorf("the read used the tenants %v, want [acme]", store.tenants)
	}
}

func TestGetModelProviderCredential_Bedrock(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{
		"aws": []byte(`{"accessKey":"AK","secretKey":"SK","sessionToken":"ST"}`),
	}}
	resp, err := modelCredServer(store).GetModelProviderCredential(
		peerCtx(t, testTenantOperatorSVID), modelCredReq("bedrock", "aws"))
	if err != nil {
		t.Fatalf("GetModelProviderCredential: %v", err)
	}
	d := resp.GetData()
	if string(d["accessKey"]) != "AK" || string(d["secretKey"]) != "SK" || string(d["sessionToken"]) != "ST" {
		t.Errorf("data = %v", d)
	}
}

func TestModelCredentialData_Refusals(t *testing.T) {
	cases := map[string]struct {
		typ string
		raw string
	}{
		"empty":                  {"openai", ""},
		"bedrock not JSON":       {"bedrock", "AKIA-plain-secret-value"},
		"bedrock no secret key":  {"bedrock", `{"accessKey":"AK"}`},
		"bedrock no access key":  {"bedrock", `{"secretKey":"SK"}`},
		"bedrock non-string val": {"bedrock", `{"accessKey":1,"secretKey":2}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := modelCredentialData(c.typ, []byte(c.raw))
			if err == nil {
				t.Fatal("the credential was accepted")
			}
			if c.raw != "" && strings.Contains(err.Error(), c.raw) {
				t.Errorf("the error holds the value: %v", err)
			}
		})
	}
}

func TestGetModelProviderCredential_OnlyTheTenantOperator(t *testing.T) {
	store := &fakeCredStore{data: map[string][]byte{"k": []byte("v")}}
	srv := modelCredServer(store)
	cases := map[string]context.Context{
		"the connector operator": peerCtx(t, testConnectorOperatorSVID),
		"the edge":               peerCtx(t, testEdgeSVID),
		"no SPIFFE ID":           peerCtx(t, ""),
		"no peer":                auth.WithTenant(context.Background(), mustTenant("acme")),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := srv.GetModelProviderCredential(ctx, modelCredReq("openai", "k"))
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
	_, err := srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), modelCredReq("openai", "k"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
}

func TestGetModelProviderCredential_MissingSecret(t *testing.T) {
	srv := modelCredServer(&fakeCredStore{data: map[string][]byte{}})
	_, err := srv.GetModelProviderCredential(peerCtx(t, testTenantOperatorSVID), modelCredReq("openai", "k"))
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v, want NotFound", err)
	}
}
