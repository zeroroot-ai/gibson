package admin

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/sdk/auth"
)

// recordingAuthorizer implements authz.Authorizer, capturing ListUsers args and
// returning canned users; all other methods are no-ops.
type recordingAuthorizer struct {
	gotObjectType, gotObject, gotRelation string
	users                                 []string
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
func (r *recordingAuthorizer) ListUsers(_ context.Context, objectType, object, relation string) ([]string, error) {
	r.gotObjectType, r.gotObject, r.gotRelation = objectType, object, relation
	return r.users, nil
}
func (r *recordingAuthorizer) StoreID() string { return "" }
func (r *recordingAuthorizer) ModelID() string { return "" }
func (r *recordingAuthorizer) Close() error    { return nil }

func TestFGASecretsPluginAssociations_PluginsBoundTo(t *testing.T) {
	rec := &recordingAuthorizer{users: []string{"user:plugin-abc", "user:tool-xyz"}}
	a := NewFGASecretsPluginAssociations(rec)
	tenant := auth.MustNewTenantID("acme")

	// stored form on the way in; the can_resolve object must use the
	// caller-facing ref (storage prefix stripped) — same format mint.go writes.
	got, err := a.PluginsBoundTo(context.Background(), tenant, "user/cred:openai-prod")
	if err != nil {
		t.Fatalf("PluginsBoundTo: %v", err)
	}
	wantObj := fmt.Sprintf("secret:tenant-%s:%s", tenant, "cred:openai-prod")
	if rec.gotObjectType != "secret" || rec.gotRelation != "can_resolve" {
		t.Errorf("objectType/relation = %q/%q, want secret/can_resolve", rec.gotObjectType, rec.gotRelation)
	}
	if rec.gotObject != wantObj {
		t.Errorf("object = %q, want %q", rec.gotObject, wantObj)
	}
	if strings.Contains(rec.gotObject, "user/") {
		t.Errorf("object must not contain the storage prefix: %q", rec.gotObject)
	}
	if len(got) != 2 || got[0] != "plugin-abc" || got[1] != "tool-xyz" {
		t.Errorf("principals = %v, want [plugin-abc tool-xyz] (user: prefix stripped)", got)
	}
}

func TestFGASecretsPluginAssociations_NilAuthorizer(t *testing.T) {
	a := NewFGASecretsPluginAssociations(nil)
	got, err := a.PluginsBoundTo(context.Background(), auth.MustNewTenantID("acme"), "cred:x")
	if err != nil || got != nil {
		t.Fatalf("nil authorizer must return (nil,nil), got (%v,%v)", got, err)
	}
}
