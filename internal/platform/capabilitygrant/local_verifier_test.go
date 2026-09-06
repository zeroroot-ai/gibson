// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package capabilitygrant

import (
	"context"
	"errors"
	"testing"

	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

func TestLocalVerifier_AcceptsAMintedGrant(t *testing.T) {
	m := newTestMinter(t)
	v := NewLocalVerifier(func() *Minter { return m })
	tok, err := m.Mint(MintRequest{
		Subject:        "component:agent:claude",
		Tenant:         "acme",
		MissionID:      "m-1",
		TaskID:         "t-1",
		RecipientClass: "agent",
		AllowedRPCs:    []string{llmCompleteRPC},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "component:agent:claude" || claims.Tenant.String() != "acme" || claims.MissionID != "m-1" {
		t.Fatalf("claims = %+v", claims)
	}
	if !claims.AllowsMethod(llmCompleteRPC) {
		t.Fatal("allowed_rpcs lost")
	}
}

func TestLocalVerifier_RefusesAForeignKey(t *testing.T) {
	signer := newTestMinter(t)
	tok, err := signer.Mint(MintRequest{
		Subject: "component:agent:claude", Tenant: "acme", MissionID: "m", TaskID: "t",
		RecipientClass: "agent", AllowedRPCs: []string{llmCompleteRPC},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewMinter(context.Background(), Config{
		Issuer: "https://test.daemon", Audience: "test-daemon",
		KeyProvider: kpAdapter{[]byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")}, KeyID: "k2",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := NewLocalVerifier(func() *Minter { return other })
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, sdkcg.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
	if _, ok := other.PublicKeyByID("k1"); ok {
		t.Fatal("k1 must not resolve on a minter that does not hold it")
	}
	if _, ok := other.PublicKeyByID("k2"); !ok {
		t.Fatal("k2 must resolve on its own minter")
	}
}

// TestNewLocalVerifier_NilSourceRefuses: the one way to misuse the constructor
// behaves exactly like "the key does not exist yet" — every grant is refused.
func TestNewLocalVerifier_NilSourceRefuses(t *testing.T) {
	v := NewLocalVerifier(nil)
	if _, err := v.Verify(context.Background(), "x.y.z"); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", err)
	}
}

// TestLocalVerifier_RefusesBeforeTheKeyExists: until the daemon loads its
// signing key a presented grant is an error, never a pass-through.
func TestLocalVerifier_RefusesBeforeTheKeyExists(t *testing.T) {
	v := NewLocalVerifier(func() *Minter { return nil })
	if _, verr := v.Verify(context.Background(), "x.y.z"); !errors.Is(verr, ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", verr)
	}
}

// TestLocalVerifier_ReadsTheMinterPerCall: the source is read on every Verify,
// so a verifier built before the daemon has its key reaches the key once it
// exists.
func TestLocalVerifier_ReadsTheMinterPerCall(t *testing.T) {
	m := newTestMinter(t)
	v := NewLocalVerifier(func() *Minter { return m })
	tok, err := m.Mint(MintRequest{
		Subject: "component:agent:claude", Tenant: "acme", MissionID: "m", TaskID: "t",
		RecipientClass: "agent", AllowedRPCs: []string{llmCompleteRPC},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, verr := v.Verify(context.Background(), tok); verr != nil {
		t.Fatalf("Verify: %v", verr)
	}
	empty := NewLocalVerifier(func() *Minter { return nil })
	if _, verr := empty.Verify(context.Background(), tok); !errors.Is(verr, ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", verr)
	}
}
