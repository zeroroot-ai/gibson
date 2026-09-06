// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Active-session tuple helpers (gibson#627 Slice 2)
// ---------------------------------------------------------------------------

func TestActiveSessionTuple(t *testing.T) {
	tup := ActiveSessionTuple("user-1", "acme")
	if tup.User != "user:user-1" {
		t.Errorf("User = %q, want user:user-1", tup.User)
	}
	if tup.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", tup.Relation)
	}
	if tup.Object != "tenant:acme" {
		t.Errorf("Object = %q, want tenant:acme", tup.Object)
	}
	if tup.ConditionName != ConditionTokenNotRevoked {
		t.Errorf("ConditionName = %q, want %q", tup.ConditionName, ConditionTokenNotRevoked)
	}
	v, ok := tup.ConditionContext[ConditionParamRevokedAt]
	if !ok {
		t.Fatal("ConditionContext missing key ConditionParamRevokedAt")
	}
	if v != EpochRevokedAt {
		t.Errorf("ConditionContext[revoked_at] = %q, want %q", v, EpochRevokedAt)
	}
}

func TestRevokedSessionTuple(t *testing.T) {
	const ts = "2026-07-03T12:00:00Z"
	tup := RevokedSessionTuple("user-2", "acme", ts)
	if tup.User != "user:user-2" {
		t.Errorf("User = %q, want user:user-2", tup.User)
	}
	if tup.Object != "tenant:acme" {
		t.Errorf("Object = %q, want tenant:acme", tup.Object)
	}
	if tup.ConditionName != ConditionTokenNotRevoked {
		t.Errorf("ConditionName = %q, want %q", tup.ConditionName, ConditionTokenNotRevoked)
	}
	v, ok := tup.ConditionContext[ConditionParamRevokedAt]
	if !ok {
		t.Fatal("ConditionContext missing key ConditionParamRevokedAt")
	}
	if v != ts {
		t.Errorf("ConditionContext[revoked_at] = %q, want %q", v, ts)
	}
	// Epoch is NOT used — revoked_at must be the supplied timestamp.
	if v == EpochRevokedAt {
		t.Errorf("RevokedSessionTuple should NOT use epoch revoked_at, got %q", v)
	}
}

// ---------------------------------------------------------------------------
// User-scoped active-session tuple helpers (gibson#1244)
// ---------------------------------------------------------------------------

func TestActiveSessionUserTuple(t *testing.T) {
	tup := ActiveSessionUserTuple("user-1")
	// Self-referential: subject and object are both the user.
	if tup.User != "user:user-1" {
		t.Errorf("User = %q, want user:user-1", tup.User)
	}
	if tup.Object != "user:user-1" {
		t.Errorf("Object = %q, want user:user-1 (self-referential)", tup.Object)
	}
	if tup.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", tup.Relation)
	}
	if tup.ConditionName != ConditionTokenNotRevoked {
		t.Errorf("ConditionName = %q, want %q", tup.ConditionName, ConditionTokenNotRevoked)
	}
	v, ok := tup.ConditionContext[ConditionParamRevokedAt]
	if !ok {
		t.Fatal("ConditionContext missing key ConditionParamRevokedAt")
	}
	if v != EpochRevokedAt {
		t.Errorf("ConditionContext[revoked_at] = %q, want %q (epoch = never revoked)", v, EpochRevokedAt)
	}
	if got := ActiveSessionUserObject("user-1"); got != "user:user-1" {
		t.Errorf("ActiveSessionUserObject = %q, want user:user-1", got)
	}
}

func TestRevokedSessionUserTuple(t *testing.T) {
	const ts = "2026-08-09T12:00:00Z"
	tup := RevokedSessionUserTuple("user-2", ts)
	if tup.User != "user:user-2" {
		t.Errorf("User = %q, want user:user-2", tup.User)
	}
	if tup.Object != "user:user-2" {
		t.Errorf("Object = %q, want user:user-2 (self-referential)", tup.Object)
	}
	if tup.Relation != "active_session" {
		t.Errorf("Relation = %q, want active_session", tup.Relation)
	}
	v, ok := tup.ConditionContext[ConditionParamRevokedAt]
	if !ok {
		t.Fatal("ConditionContext missing key ConditionParamRevokedAt")
	}
	if v != ts {
		t.Errorf("ConditionContext[revoked_at] = %q, want %q", v, ts)
	}
	// Epoch is NOT used — revoked_at must be the supplied timestamp.
	if v == EpochRevokedAt {
		t.Errorf("RevokedSessionUserTuple should NOT use epoch revoked_at, got %q", v)
	}
}

func TestComponentObject(t *testing.T) {
	if got := ComponentObject("tool", "nmap"); got != "component:tool/nmap" {
		t.Fatalf("ComponentObject(tool, nmap) = %q", got)
	}
}

func TestConnectorComponentObject(t *testing.T) {
	if got := ConnectorComponentObject("gitlab"); got != "component:connector/gitlab" {
		t.Fatalf("ConnectorComponentObject(gitlab) = %q", got)
	}
	// Idempotent under CanonicalComponentResource (ADR-0015): a kind-qualified
	// name round-trips to the canonical prefixed object.
	got, err := CanonicalComponentResource("connector:gitlab")
	if err != nil || got != "component:connector/gitlab" {
		t.Fatalf("CanonicalComponentResource(connector:gitlab) = %q, err=%v", got, err)
	}
}

func TestPluginObject(t *testing.T) {
	if got := PluginObject("acme", "gitlab"); got != "plugin:acme/gitlab" {
		t.Fatalf("PluginObject(acme, gitlab) = %q", got)
	}
}

func TestCanonicalComponentResource(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		want     string
		wantErr  bool
	}{
		{"bare name fails closed", "nmap", "", true},
		{"hyphenated bare name fails closed", "nmap-agent", "", true},
		{"legacy kind-less object fails closed", "component:nmap", "", true},
		{"unknown kind object fails closed", "component:sensor/x", "", true},
		// Slash form "<kind>/<name>" — the object minus its "component:" prefix,
		// the natural thing a UI or user types. Accepted (gibson#1600 follow-up).
		{"slash form agent", "agent/zerocool", "component:agent/zerocool", false},
		{"slash form hyphenated name", "agent/zerocool-claude", "component:agent/zerocool-claude", false},
		{"slash form tool", "tool/nmap", "component:tool/nmap", false},
		{"slash form unknown kind fails closed", "sensor/x", "", true},
		{"slash form empty name fails closed", "agent/", "", true},
		{"kind tool", "tool:nmap", "component:tool/nmap", false},
		{"kind agent", "agent:scan-controller", "component:agent/scan-controller", false},
		{"kind plugin two-segment", "plugin:gitlab", "component:plugin/gitlab", false},
		{"kind connector", "connector:gitlab", "component:connector/gitlab", false},
		{"already canonical tool", "component:tool/nmap", "component:tool/nmap", false},
		{"already canonical agent", "component:agent/zerocool", "component:agent/zerocool", false},
		{"legacy colon object tool", "component:tool:nmap", "component:tool/nmap", false},
		{"legacy colon object plugin", "component:plugin:gitlab", "component:plugin/gitlab", false},
		{"typed plugin object (colon-free) untouched", "plugin:acme/gitlab", "plugin:acme/gitlab", false},
		{"legacy colon typed plugin object untouched", "plugin:acme:gitlab", "plugin:acme:gitlab", false},
		{"other typed ref untouched", "mission:abc-123", "mission:abc-123", false},
		{"kind tool hyphenated name", "tool:web-scanner", "component:tool/web-scanner", false},
		{"three-segment non-component untouched", "team:acme:ops", "team:acme:ops", false},
		{"component with non-kind middle untouched", "component:acme:thing", "component:acme:thing", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalComponentResource(tc.resource)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("CanonicalComponentResource(%q) = %q, want error", tc.resource, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("CanonicalComponentResource(%q) unexpected error: %v", tc.resource, err)
			}
			if got != tc.want {
				t.Fatalf("CanonicalComponentResource(%q) = %q, want %q", tc.resource, got, tc.want)
			}
		})
	}
}

// The secret FGA object id must be colon-free in the id portion: OpenFGA
// v1.15.1 (the platform pin) rejects a colon in the id with "invalid 'object'
// field format" on BOTH Write and Check. A secret ref is category-prefixed
// with a colon (cred:, provider_config:), so SecretObject folds it to keep the
// object legal — and write and check must produce the identical string.
func TestSecretObject_IsColonFreeInTheIDPortion(t *testing.T) {
	cases := []struct {
		name       string
		tenant     string
		ref        string
		wantObject string
	}{
		{"cred category", "primary", "cred:openai-prod", "secret:tenant-primary/cred@openai-prod"},
		{"provider_config category", "acme", "provider_config:vault", "secret:tenant-acme/provider_config@vault"},
		{"connector slashed name", "primary", "cred:connector/connector-gitlab/access", "secret:tenant-primary/cred@connector/connector-gitlab/access"},
		{"already colon-free", "primary", "plainref", "secret:tenant-primary/plainref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SecretObject(tc.tenant, tc.ref)
			if got != tc.wantObject {
				t.Fatalf("SecretObject(%q, %q) = %q, want %q", tc.tenant, tc.ref, got, tc.wantObject)
			}
			// The id (everything after the first "secret:") must contain no colon.
			id := got[len("secret:"):]
			if strings.ContainsRune(id, ':') {
				t.Fatalf("object id %q still contains a colon — OpenFGA v1.15.1 rejects it", id)
			}
			// Write and check both call SecretObject, so the deriver mirror
			// must produce the identical string.
			if SecretObjectFromDeriver(tc.tenant, tc.ref) != got {
				t.Fatal("SecretObjectFromDeriver disagrees with SecretObject — write and check would never match")
			}
		})
	}
}

// RefFromObjectSegment is the reverse of the fold refToObjectSegment applies
// inside SecretObject: it recovers the exact broker secret ref from the
// "@"-encoded id segment. uriToRef (secrets_admin) relies on it to turn an
// audit-log secret object id back into the ref a broker lookup needs. The two
// must round-trip for every ref, and "@" is chosen precisely because it never
// occurs in a broker secret ref, so the substitution is unambiguous.
func TestRefFromObjectSegment_RoundTripsWithSecretObject(t *testing.T) {
	refs := []string{
		"cred:openai-prod",
		"provider_config:vault",
		"cred:connector/connector-gitlab/access",
		"plainref",
		"cred:a:b:c",
		"",
	}
	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			seg := refToObjectSegment(ref)
			if strings.ContainsRune(seg, ':') {
				t.Fatalf("refToObjectSegment(%q) = %q still contains a colon", ref, seg)
			}
			if got := RefFromObjectSegment(seg); got != ref {
				t.Fatalf("round-trip failed: RefFromObjectSegment(refToObjectSegment(%q)) = %q", ref, got)
			}
		})
	}
}

// RefFromObjectSegment recovers the ref from the segment after the tenant
// prefix of a full SecretObject id — the exact slice uriToRef feeds it.
func TestRefFromObjectSegment_RecoversRefFromSecretObject(t *testing.T) {
	const tenant = "acme"
	cases := []struct {
		ref string
	}{
		{"cred:openai-prod"},
		{"provider_config:vault"},
		{"cred:connector/connector-gitlab/access"},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			obj := SecretObject(tenant, tc.ref)
			// Mirror uriToRef: strip "secret:tenant-<tenant>/" then decode.
			prefix := "secret:tenant-" + tenant + "/"
			if !strings.HasPrefix(obj, prefix) {
				t.Fatalf("object %q missing expected prefix %q", obj, prefix)
			}
			seg := obj[len(prefix):]
			if got := RefFromObjectSegment(seg); got != tc.ref {
				t.Fatalf("RefFromObjectSegment(%q) = %q, want %q", seg, got, tc.ref)
			}
		})
	}
}
