// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"errors"
	"testing"
	"time"
)

func validCreate() CreateInput {
	return CreateInput{
		Name:               "nightly",
		OwnerKind:          OwnerUser,
		OwnerID:            "alice",
		DesiredCount:       2,
		LoginShape:         LoginShapeAPIKey,
		ProviderConfigName: "tenant-anthropic",
	}
}

func TestCreateInput_Validate_FillsTheDefaults(t *testing.T) {
	in := validCreate()
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.AgentName != DefaultAgentName {
		t.Errorf("agent = %q, want %q", in.AgentName, DefaultAgentName)
	}
	if in.MaxJobsInFlight != DefaultMaxJobsInFlight {
		t.Errorf("cap = %d, want %d", in.MaxJobsInFlight, DefaultMaxJobsInFlight)
	}
	if in.StaleLimit != DefaultStaleLimit {
		t.Errorf("stale limit = %s, want %s", in.StaleLimit, DefaultStaleLimit)
	}
	if in.SpillPolicy != SpillQueue {
		t.Errorf("spill = %q, want queue", in.SpillPolicy)
	}
}

func TestCreateInput_Validate_TrimsTheName(t *testing.T) {
	in := validCreate()
	in.Name = "  nightly  "
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.Name != "nightly" {
		t.Errorf("name = %q, want the trimmed name", in.Name)
	}
}

func TestCreateInput_Validate_Refusals(t *testing.T) {
	cases := map[string]func(*CreateInput){
		"no name":                  func(in *CreateInput) { in.Name = "   " },
		"no owner kind":            func(in *CreateInput) { in.OwnerKind = "" },
		"unknown owner kind":       func(in *CreateInput) { in.OwnerKind = "robot" },
		"no owner id":              func(in *CreateInput) { in.OwnerID = "" },
		"unknown login shape":      func(in *CreateInput) { in.LoginShape = "oauth" },
		"no login shape":           func(in *CreateInput) { in.LoginShape = "" },
		"api key with no provider": func(in *CreateInput) { in.ProviderConfigName = "" },
		"negative desired count":   func(in *CreateInput) { in.DesiredCount = -1 },
		"negative job cap":         func(in *CreateInput) { in.MaxJobsInFlight = -1 },
		"negative stale limit":     func(in *CreateInput) { in.StaleLimit = -time.Second },
		"unknown spill policy":     func(in *CreateInput) { in.SpillPolicy = "drop" },
		"tenant-owned subscription": func(in *CreateInput) {
			in.OwnerKind = OwnerTenant
			in.LoginShape = LoginShapeSubscription
			in.ProviderConfigName = ""
		},
		"subscription with provider": func(in *CreateInput) { in.LoginShape = LoginShapeSubscription },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validCreate()
			mutate(&in)
			err := in.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

// TestCreateInput_Validate_SubscriptionForAPerson: the one login shape that
// stores nothing is valid exactly when a person owns the bank and no provider
// configuration is named.
func TestCreateInput_Validate_SubscriptionForAPerson(t *testing.T) {
	in := CreateInput{
		Name: "mine", OwnerKind: OwnerUser, OwnerID: "alice",
		DesiredCount: 1, LoginShape: LoginShapeSubscription,
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestUpdateInput_Validate(t *testing.T) {
	neg := int32(-1)
	negDur := -time.Second
	bad := SpillPolicy("drop")
	for name, in := range map[string]UpdateInput{
		"negative desired count": {DesiredCount: &neg},
		"negative job cap":       {MaxJobsInFlight: &neg},
		"negative stale limit":   {StaleLimit: &negDur},
		"unknown spill policy":   {SpillPolicy: &bad},
	} {
		t.Run(name, func(t *testing.T) {
			if err := in.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
	ok := int32(3)
	if err := (&UpdateInput{DesiredCount: &ok}).Validate(); err != nil {
		t.Errorf("a valid update must pass: %v", err)
	}
	if err := (&UpdateInput{}).Validate(); err != nil {
		t.Errorf("an empty update changes nothing and must pass: %v", err)
	}
}

func TestLoginShapeHelpers(t *testing.T) {
	for _, s := range []LoginShape{LoginShapeSubscription, LoginShapeAPIKey, LoginShapeBedrock, LoginShapeVertex, LoginShapeFoundry} {
		if !IsLoginShape(s) {
			t.Errorf("%q must be a login shape", s)
		}
	}
	if IsLoginShape("oauth") {
		t.Error("oauth is not a login shape")
	}
	if NeedsProviderConfig(LoginShapeSubscription) {
		t.Error("a subscription stores no credential, so it needs no provider configuration")
	}
	for _, s := range []LoginShape{LoginShapeAPIKey, LoginShapeBedrock, LoginShapeVertex, LoginShapeFoundry} {
		if !NeedsProviderConfig(s) {
			t.Errorf("%q draws its credential from a provider configuration", s)
		}
	}
	if len(LoginShapeNames()) != 5 {
		t.Errorf("names = %v, want every shape", LoginShapeNames())
	}
}

func TestIsSpillPolicy(t *testing.T) {
	if !IsSpillPolicy(SpillQueue) || !IsSpillPolicy(SpillEphemeral) {
		t.Error("both policies must be recognised")
	}
	if IsSpillPolicy("drop") {
		t.Error("drop is not a spill policy")
	}
}

func TestClampPageSize(t *testing.T) {
	if got := clampPageSize(0); got != DefaultPageSize {
		t.Errorf("0 -> %d, want the default", got)
	}
	if got := clampPageSize(-5); got != DefaultPageSize {
		t.Errorf("negative -> %d, want the default", got)
	}
	if got := clampPageSize(10); got != 10 {
		t.Errorf("10 -> %d", got)
	}
	if got := clampPageSize(MaxPageSize + 1); got != MaxPageSize {
		t.Errorf("above the maximum -> %d, want it capped, never refused", got)
	}
}

func TestPageToken_RoundTrips(t *testing.T) {
	at := time.Date(2026, 9, 1, 12, 0, 0, 123456789, time.UTC)
	token := encodeToken(cursor{at: &at, id: "bank-7"})
	if token == "" {
		t.Fatal("a cursor with a time must encode")
	}
	got, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}
	if got.id != "bank-7" || !got.at.Equal(at) {
		t.Fatalf("cursor = %+v, want the one encoded", got)
	}
}

func TestPageToken_EmptyAndUnreadable(t *testing.T) {
	got, err := decodeToken("")
	if err != nil || got.at != nil {
		t.Fatalf("an empty token starts at the newest: %+v %v", got, err)
	}
	if encodeToken(cursor{}) != "" {
		t.Error("a cursor with no time encodes to no token")
	}
	for _, bad := range []string{"!!!not-base64!!!", "bm90aGluZw"} {
		if _, err := decodeToken(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("decodeToken(%q) = %v, want ErrInvalid; a silent restart would loop a client forever", bad, err)
		}
	}
}

func TestTrimPage(t *testing.T) {
	at := time.Now().UTC()
	rows := []*Bank{{ID: "a", CreatedAt: at}, {ID: "b", CreatedAt: at}, {ID: "c", CreatedAt: at}}
	key := func(b *Bank) cursor { return cursor{at: &b.CreatedAt, id: b.ID} }

	page, next, err := trimPage(rows, 2, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || next == "" {
		t.Fatalf("page = %d next = %q, want two rows and a token", len(page), next)
	}
	c, err := decodeToken(next)
	if err != nil || c.id != "b" {
		t.Fatalf("next token points at %+v, want the last row of the page", c)
	}

	page, next, err = trimPage(rows[:2], 2, key)
	if err != nil || len(page) != 2 || next != "" {
		t.Fatalf("a full last page carries no token: %d %q %v", len(page), next, err)
	}
}

func TestStaleLimitSeconds(t *testing.T) {
	if got := staleLimitSeconds(90 * time.Minute); got != 5400 {
		t.Errorf("90m -> %d seconds", got)
	}
	if got := staleLimitSeconds(0); got != 0 {
		t.Errorf("0 -> %d", got)
	}
}

func TestNewPostgresStore_NeedsAPool(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a store with no pool must not be constructible")
		}
	}()
	NewPostgresStore(nil)
}
