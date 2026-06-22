package fga

import (
	"strings"
	"testing"
)

const testYAML = `entries:
  "/test.v1.S/Public":
    unauthenticated: true
  "/test.v1.S/Member":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
      - SERVICE
  "/test.v1.S/Admin":
    relation: "platform_operator"
    object_type: "system_tenant"
    object_deriver: "system_tenant"
    allowed_identities:
      - PLATFORM_OPERATOR
`

func TestLoadRegistry_HappyPath(t *testing.T) {
	r, err := LoadRegistry([]byte(testYAML))
	if err != nil {
		t.Fatal(err)
	}
	if r.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", r.Len())
	}
	pub, ok := r.Lookup("/test.v1.S/Public")
	if !ok || !pub.Unauthenticated {
		t.Errorf("Public entry mismatch: %+v ok=%v", pub, ok)
	}
	mem, ok := r.Lookup("/test.v1.S/Member")
	if !ok {
		t.Fatal("Member missing")
	}
	if mem.Relation != "member" || mem.ObjectType != "tenant" || mem.ObjectDeriver != "tenant_from_identity" {
		t.Errorf("Member fields wrong: %+v", mem)
	}
	if !mem.AllowedIdentities.Has(IdentityUser) || !mem.AllowedIdentities.Has(IdentityService) {
		t.Errorf("Member identities: %s", mem.AllowedIdentities.String())
	}
	if mem.AllowedIdentities.Has(IdentityComponent) {
		t.Errorf("Member should not allow COMPONENT")
	}
}

func TestLoadRegistry_EmptyBytes(t *testing.T) {
	_, err := LoadRegistry([]byte{})
	if err == nil {
		t.Fatal("expected error on empty input")
	}
}

func TestLoadRegistry_NoEntries(t *testing.T) {
	_, err := LoadRegistry([]byte("entries: {}"))
	if err == nil {
		t.Fatal("expected error on empty entries")
	}
}

func TestLoadRegistry_UnauthenticatedWithRelation_Rejected(t *testing.T) {
	bad := `entries:
  "/x/y":
    unauthenticated: true
    relation: "member"
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestLoadRegistry_MissingFields(t *testing.T) {
	bad := `entries:
  "/x/y":
    relation: "member"
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil {
		t.Fatal("expected error: missing object_type/deriver/identities")
	}
}

func TestLoadRegistry_UnknownIdentity(t *testing.T) {
	bad := `entries:
  "/x/y":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities: [BOGUS]
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil || !strings.Contains(err.Error(), "unknown allowed_identities") {
		t.Fatalf("expected unknown-identity error, got %v", err)
	}
}

// ---- self-mode parser tests (spec: self-mode-authz) ----

const testYAMLWithSelf = `entries:
  "/test.v1.S/Public":
    unauthenticated: true
  "/test.v1.S/Member":
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
  "/test.v1.S/SelfRead":
    self: true
    allowed_identities:
      - USER
`

// TestLoadRegistry_SelfMode_Valid — self:true + USER is a valid shape.
func TestLoadRegistry_SelfMode_Valid(t *testing.T) {
	r, err := LoadRegistry([]byte(testYAMLWithSelf))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	e, ok := r.Lookup("/test.v1.S/SelfRead")
	if !ok {
		t.Fatal("SelfRead entry missing")
	}
	if !e.Self {
		t.Errorf("expected Self==true, got false: %+v", e)
	}
	if !e.AllowedIdentities.Has(IdentityUser) {
		t.Errorf("expected USER in AllowedIdentities, got %s", e.AllowedIdentities.String())
	}
	if e.Unauthenticated {
		t.Error("Self entry must not have Unauthenticated==true")
	}
	if e.Relation != "" || e.ObjectType != "" || e.ObjectDeriver != "" {
		t.Errorf("Self entry must not have rule fields set: %+v", e)
	}
}

// TestLoadRegistry_SelfAndUnauthenticated_Rejected — self:true AND unauthenticated:true is invalid.
func TestLoadRegistry_SelfAndUnauthenticated_Rejected(t *testing.T) {
	bad := `entries:
  "/x/y":
    self: true
    unauthenticated: true
    allowed_identities:
      - USER
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil {
		t.Fatal("expected error for self+unauthenticated")
	}
	if !strings.Contains(err.Error(), "self-mode-authz") {
		t.Errorf("error must reference self-mode-authz, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/x/y") {
		t.Errorf("error must name the offending method, got: %v", err)
	}
}

// TestLoadRegistry_SelfAndRelation_Rejected — self:true with rule fields is invalid.
func TestLoadRegistry_SelfAndRelation_Rejected(t *testing.T) {
	bad := `entries:
  "/x/Self":
    self: true
    relation: "member"
    object_type: "tenant"
    object_deriver: "tenant_from_identity"
    allowed_identities:
      - USER
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil {
		t.Fatal("expected error for self+rule fields")
	}
	if !strings.Contains(err.Error(), "self-mode-authz") {
		t.Errorf("error must reference self-mode-authz, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/x/Self") {
		t.Errorf("error must name the offending method, got: %v", err)
	}
}

// TestLoadRegistry_SelfWithoutAllowedIdentities_Rejected — self:true without allowed_identities is invalid.
func TestLoadRegistry_SelfWithoutAllowedIdentities_Rejected(t *testing.T) {
	bad := `entries:
  "/x/NoIds":
    self: true
`
	_, err := LoadRegistry([]byte(bad))
	if err == nil {
		t.Fatal("expected error for self without allowed_identities")
	}
	if !strings.Contains(err.Error(), "self-mode-authz") {
		t.Errorf("error must reference self-mode-authz, got: %v", err)
	}
}

// TestLoadRegistry_BackwardCompat_NoSelfKey — legacy YAML without 'self' keys
// loads cleanly and every entry has Self==false.
func TestLoadRegistry_BackwardCompat_NoSelfKey(t *testing.T) {
	r, err := LoadRegistry([]byte(testYAML))
	if err != nil {
		t.Fatalf("unexpected error on legacy YAML: %v", err)
	}
	for _, method := range r.Methods() {
		e, _ := r.Lookup(method)
		if e.Self {
			t.Errorf("legacy entry %q has Self==true; expected false for backward-compat", method)
		}
	}
}

func TestLookup_Miss(t *testing.T) {
	r, _ := LoadRegistry([]byte(testYAML))
	if _, ok := r.Lookup("/missing/X"); ok {
		t.Fatal("expected miss")
	}
}

func TestIdentityClass_String(t *testing.T) {
	cases := []struct {
		c    IdentityClass
		want string
	}{
		{0, "NONE"},
		{IdentityUser, "USER"},
		{IdentityUser | IdentityService, "USER/SERVICE"},
		{IdentityUser | IdentityService | IdentityComponent | IdentityPlatformOperator, "USER/SERVICE/COMPONENT/PLATFORM_OPERATOR"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}
