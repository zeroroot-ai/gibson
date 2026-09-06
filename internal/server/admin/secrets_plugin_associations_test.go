// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// recordingAuthorizer implements authz.Authorizer, capturing the typed-listing
// args and returning canned subjects; all other methods are no-ops.
type recordingAuthorizer struct {
	gotObjectType, gotObject, gotRelation, gotUserType string
	users                                              []string
}

func (r *recordingAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (r *recordingAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (r *recordingAuthorizer) Write(context.Context, []authz.Tuple) error  { return nil }
func (r *recordingAuthorizer) Delete(context.Context, []authz.Tuple) error { return nil }
func (r *recordingAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

// ListUsers must not be reached: secret.can_resolve is declared
// [plugin_principal] in model.fga, so a "user"-filtered listing can only ever
// answer empty. authz.ListUsers refuses it outright; this double fails the test
// if the reader regresses to it.
func (r *recordingAuthorizer) ListUsers(_ context.Context, objectType, _, relation string) ([]string, error) {
	return nil, fmt.Errorf("ListUsers(%s, %s) is user-filtered and can never match a plugin_principal", objectType, relation)
}
func (r *recordingAuthorizer) StoreID() string { return "" }
func (r *recordingAuthorizer) ModelID() string { return "" }
func (r *recordingAuthorizer) Close() error    { return nil }

func TestFGASecretsPluginAssociations_PluginsBoundTo(t *testing.T) {
	rec := &recordingAuthorizer{users: []string{"plugin_principal:plugin-abc", "plugin_principal:tool-xyz"}}
	a := NewFGASecretsPluginAssociations(rec)
	tenant := auth.MustNewTenantID("acme")

	// The stored key is colon-flat at the KV root (H1, gibson#1106) and equals
	// the caller-facing ref; the can_resolve object uses that ref directly —
	// same format mint.go writes.
	got, err := a.PluginsBoundTo(context.Background(), tenant, "cred:openai-prod")
	if err != nil {
		t.Fatalf("PluginsBoundTo: %v", err)
	}
	wantObj := fmt.Sprintf("secret:tenant-%s/%s", tenant, "cred:openai-prod")
	if rec.gotObjectType != "secret" || rec.gotRelation != "can_resolve" {
		t.Errorf("objectType/relation = %q/%q, want secret/can_resolve", rec.gotObjectType, rec.gotRelation)
	}
	// The subject type is the whole point: model.fga declares can_resolve as
	// [plugin_principal], and a "user" filter answers empty for every secret.
	if rec.gotUserType != "plugin_principal" {
		t.Errorf("userType = %q, want plugin_principal", rec.gotUserType)
	}
	if rec.gotObject != wantObj {
		t.Errorf("object = %q, want %q", rec.gotObject, wantObj)
	}
	if strings.Contains(rec.gotObject, "user/") {
		t.Errorf("object must not contain the retired storage prefix: %q", rec.gotObject)
	}
	if len(got) != 2 || got[0] != "plugin-abc" || got[1] != "tool-xyz" {
		t.Errorf("principals = %v, want [plugin-abc tool-xyz] (plugin_principal: prefix stripped)", got)
	}
}

func TestFGASecretsPluginAssociations_NilAuthorizer(t *testing.T) {
	a := NewFGASecretsPluginAssociations(nil)
	got, err := a.PluginsBoundTo(context.Background(), auth.MustNewTenantID("acme"), "cred:x")
	if err != nil || got != nil {
		t.Fatalf("nil authorizer must return (nil,nil), got (%v,%v)", got, err)
	}
}

func (r *recordingAuthorizer) ListUsersOfType(_ context.Context, objectType, object, relation, userType string) ([]string, error) {
	r.gotObjectType, r.gotObject, r.gotRelation, r.gotUserType = objectType, object, relation, userType
	return r.users, nil
}
