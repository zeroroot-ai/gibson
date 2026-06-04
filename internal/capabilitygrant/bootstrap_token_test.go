package capabilitygrant

import (
	"strings"
	"testing"
	"time"
)

func TestBootstrapToken_RoundTrip(t *testing.T) {
	m := newTestMinter(t)
	want := BootstrapClaims{
		TenantID:    "acme",
		OwnerUserID: "user-123",
		PrincipalID: "agent_principal:456",
		Kind:        "agent",
		Name:        "hello-agent",
	}
	tok, err := m.MintBootstrapToken(want, 0)
	if err != nil {
		t.Fatalf("MintBootstrapToken: %v", err)
	}
	got, err := m.VerifyBootstrapToken(tok)
	if err != nil {
		t.Fatalf("VerifyBootstrapToken: %v", err)
	}
	if *got != want {
		t.Errorf("claims = %+v, want %+v", *got, want)
	}
}

func TestBootstrapToken_RequiresIdentity(t *testing.T) {
	m := newTestMinter(t)
	if _, err := m.MintBootstrapToken(BootstrapClaims{Kind: "agent"}, 0); err == nil {
		t.Fatal("expected error minting without tenant/owner/principal")
	}
}

// A per-RPC CG-JWT (typ "JWT", different audience) must NOT verify as a bootstrap
// token — otherwise a runtime token could be replayed at the register endpoint.
func TestBootstrapToken_RejectsPerRPCCGJWT(t *testing.T) {
	m := newTestMinter(t)
	cgjwt, err := m.Mint(MintRequest{
		Subject:     "agent-1",
		Tenant:      "acme",
		MissionID:   "m",
		TaskID:      "t",
		AllowedRPCs: []string{"/x.S/Y"},
		TTL:         5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := m.VerifyBootstrapToken(cgjwt); err == nil {
		t.Fatal("expected a per-RPC CG-JWT to be rejected as a bootstrap token")
	}
}

func TestBootstrapToken_RejectsTampered(t *testing.T) {
	m := newTestMinter(t)
	tok, err := m.MintBootstrapToken(BootstrapClaims{
		TenantID: "acme", OwnerUserID: "u", PrincipalID: "agent_principal:1",
	}, 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Flip a character in the payload segment.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token shape")
	}
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	if _, err := m.VerifyBootstrapToken(strings.Join(parts, ".")); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}
