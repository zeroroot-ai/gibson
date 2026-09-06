// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"strings"
	"testing"
	"time"
)

func validGrant() *Grant {
	return &Grant{
		RefreshToken:  "rt-1",
		TokenEndpoint: "https://gitlab.example.com/oauth/token",
		ClientID:      "client-abc",
		Scope:         "api",
		AuthorizedBy:  "alice@example.com",
		AuthorizedAt:  time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestGrantValidate_AcceptsACompleteGrant(t *testing.T) {
	if err := validGrant().Validate(); err != nil {
		t.Fatalf("a complete grant must validate: %v", err)
	}
}

// Each field is required for a different reason, so each is refused
// separately rather than by one "looks empty" check.
func TestGrantValidate_RefusesEachMissingField(t *testing.T) {
	cases := []struct {
		field  string
		mutate func(*Grant)
	}{
		{"refresh_token", func(g *Grant) { g.RefreshToken = "" }},
		{"token_endpoint", func(g *Grant) { g.TokenEndpoint = "" }},
		{"client_id", func(g *Grant) { g.ClientID = "" }},
		// Not cosmetic: a grant with no recorded human is a service account
		// nobody is accountable for, which ADR-0064 refuses outright.
		{"authorized_by", func(g *Grant) { g.AuthorizedBy = "" }},
	}
	for _, tc := range cases {
		g := validGrant()
		tc.mutate(g)
		err := g.Validate()
		if err == nil {
			t.Errorf("a grant missing %s must be refused", tc.field)
			continue
		}
		if !strings.Contains(err.Error(), tc.field) {
			t.Errorf("the error must name %s, got %v", tc.field, err)
		}
	}
}

func TestGrantValidate_NamesEveryMissingFieldAtOnce(t *testing.T) {
	err := (&Grant{}).Validate()
	if err == nil {
		t.Fatal("an empty grant must be refused")
	}
	// One round trip should tell an operator everything that is wrong, not the
	// first thing.
	for _, f := range []string{"refresh_token", "token_endpoint", "client_id", "authorized_by"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error should name %s: %v", f, err)
		}
	}
}

func TestMarshalGrant_RefusesAnIncompleteGrant(t *testing.T) {
	if _, err := MarshalGrant(&Grant{RefreshToken: "r"}); err == nil {
		t.Fatal("marshalling an incomplete grant must fail rather than store it")
	}
}

func TestMarshalGrant_RoundTrips(t *testing.T) {
	blob, err := MarshalGrant(validGrant())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalGrant(blob)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RefreshToken != "rt-1" || got.AuthorizedBy != "alice@example.com" {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if !got.AuthorizedAt.Equal(validGrant().AuthorizedAt) {
		t.Errorf("round trip lost the authorization time: %v", got.AuthorizedAt)
	}
}

func TestUnmarshalGrant_Empty(t *testing.T) {
	if _, err := UnmarshalGrant(nil); err == nil {
		t.Fatal("an empty grant must be refused")
	}
}

// A parse failure must name the secret, never its content: the bytes are a
// refresh token and must not reach a log through an error string.
func TestUnmarshalGrant_MalformedErrorCarriesNoContent(t *testing.T) {
	raw := []byte(`{"refresh_token":"rt-super-secret",`)
	_, err := UnmarshalGrant(raw)
	if err == nil {
		t.Fatal("malformed JSON must be refused")
	}
	if strings.Contains(err.Error(), "rt-super-secret") {
		t.Errorf("the error leaked grant content: %v", err)
	}
}

func TestUnmarshalGrant_WellFormedButIncomplete(t *testing.T) {
	if _, err := UnmarshalGrant([]byte(`{"refresh_token":"r"}`)); err == nil {
		t.Fatal("a parsable but incomplete grant must be refused")
	}
}

// The two names must never collide: one is platform-only and the other is
// bound to the connector, so a naming bug would hand a vendor server the
// refresh token.
func TestSecretNames_AreDistinctAndScopedToTheConnector(t *testing.T) {
	g, a := GrantSecretName("gitlab"), AccessSecretName("gitlab")
	if g == a {
		t.Fatal("the grant and access secret names must differ")
	}
	for _, n := range []string{g, a} {
		if !strings.HasPrefix(n, "cred:connector/gitlab/") {
			t.Errorf("%q is not scoped to the connector", n)
		}
	}
	if GrantSecretName("gitlab") == GrantSecretName("github") {
		t.Error("two connectors must not share a grant name")
	}
}

// A static grant (ADR-0015, an `auth: secret` connector) carries no refresh
// material: it validates on the accountable human alone and round-trips with
// the static marker intact.
func TestStaticGrant_ValidatesWithoutRefreshMaterial(t *testing.T) {
	g := &Grant{Static: true, AuthorizedBy: "user:user-1", AuthorizedAt: time.Unix(1_700_000_000, 0).UTC()}
	blob, err := MarshalGrant(g)
	if err != nil {
		t.Fatalf("a static grant must marshal without refresh material: %v", err)
	}
	got, err := UnmarshalGrant(blob)
	if err != nil {
		t.Fatalf("unmarshal static grant: %v", err)
	}
	if !got.Static || got.AuthorizedBy != "user:user-1" {
		t.Errorf("round trip lost fields: %+v", got)
	}
}

// The accountable human is required for a static grant exactly as for an
// OAuth one: a credential nobody supplied is a service account nobody owns.
func TestStaticGrant_StillRequiresTheHuman(t *testing.T) {
	if err := (&Grant{Static: true}).Validate(); err == nil {
		t.Fatal("a static grant with no authorized_by must be refused")
	}
}
