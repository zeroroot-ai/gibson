// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// runActingUser runs the unary interceptor and returns the acting user the
// handler saw.
func runActingUser(t *testing.T, ctx context.Context) (string, bool) {
	t.Helper()
	var got string
	var ok bool
	_, err := actingUserUnary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/y"}, func(ctx context.Context, _ any) (any, error) {
		got, ok = auth.ActingUserFromContext(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	return got, ok
}

func TestActingUser_AHumanCallSetsTheVerifiedSubject(t *testing.T) {
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "312345678901234567", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser,
	})
	got, ok := runActingUser(t, ctx)
	if !ok || got != "312345678901234567" {
		t.Fatalf("acting user = %q, %v; want the verified subject", got, ok)
	}
}

func TestActingUser_AServiceOrComponentCallSetsNone(t *testing.T) {
	for name, id := range map[string]auth.Identity{
		"service":   {Subject: "dashboard-sa", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialClientCredentials},
		"component": {Subject: "agent_principal:abc", CredentialType: auth.CredentialCapabilityGrant},
		"spiffe":    {Subject: "spiffe://zeroroot.ai/ns/gibson/sa/e2e-runner", Issuer: auth.Issuer("spiffe"), CredentialType: auth.CredentialType("spiffe")},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := runActingUser(t, auth.WithIdentity(context.Background(), id)); ok {
				t.Fatalf("a %s identity set acting user %q", name, got)
			}
		})
	}
}

func TestActingUser_AClientHeaderIsIgnored(t *testing.T) {
	md := grpcmetadata.Pairs("x-gibson-acting-user", "victim", "x-acting-user", "victim")
	ctx := grpcmetadata.NewIncomingContext(context.Background(), md)
	ctx = auth.WithIdentity(ctx, auth.Identity{Subject: "agent_principal:abc", CredentialType: auth.CredentialCapabilityGrant})
	if got, ok := runActingUser(t, ctx); ok {
		t.Fatalf("a client header set acting user %q", got)
	}
	// A human call still gets its own subject, not the header value.
	ctx = auth.WithIdentity(grpcmetadata.NewIncomingContext(context.Background(), md),
		auth.Identity{Subject: "alice", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser})
	if got, _ := runActingUser(t, ctx); got != "alice" {
		t.Fatalf("acting user = %q, want the verified subject alice", got)
	}
}

func TestActingUser_NoIdentitySetsNone(t *testing.T) {
	if got, ok := runActingUser(t, context.Background()); ok {
		t.Fatalf("no identity set acting user %q", got)
	}
}

func TestActingUser_TheStreamInterceptorSetsIt(t *testing.T) {
	ctx := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "alice", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser,
	})
	var got string
	err := actingUserStream(nil, &serverStreamCtxOverride{ctx: ctx}, &grpc.StreamServerInfo{}, func(_ any, ss grpc.ServerStream) error {
		got, _ = auth.ActingUserFromContext(ss.Context())
		return nil
	})
	if err != nil || got != "alice" {
		t.Fatalf("stream acting user = %q, %v", got, err)
	}
}
