package zitadel_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// The tenant org of a self-serve signup (gibson#1188): made through
// Zitadel v2, refused on a taken name, removed on a failed signup, and never
// the platform org.

func newOrgClient(t *testing.T, handler http.HandlerFunc) *zitadel.Client {
	t.Helper()
	srv := zitadelconntest.New(t, "", handler)
	client, err := zitadel.New(context.Background(), testConfig(t, srv))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { closeClient(t, client) })
	return client
}

func TestCreateOrganization_PostsTheNameAndReturnsTheID(t *testing.T) {
	var gotMethod, gotPath, gotOrgHeader string
	var gotBody map[string]interface{}
	client := newOrgClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotOrgHeader = r.Method, r.URL.Path, r.Header.Get("x-zitadel-orgid")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		jsonResp(w, http.StatusCreated, map[string]string{"organizationId": "org-new"})
	})
	id, err := client.CreateOrganization(context.Background(), "Acme Red Team")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if id != "org-new" {
		t.Errorf("org id = %q, want org-new", id)
	}
	if gotMethod != http.MethodPost || gotPath != "/v2/organizations" {
		t.Errorf("%s %s, want POST /v2/organizations", gotMethod, gotPath)
	}
	if gotBody["name"] != "Acme Red Team" {
		t.Errorf("body name = %v", gotBody["name"])
	}
	if gotOrgHeader != "" {
		t.Errorf("an org create carried an org header %q", gotOrgHeader)
	}
}

func TestCreateOrganization_TakenNameIsAlreadyExists(t *testing.T) {
	calls := 0
	client := newOrgClient(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		jsonResp(w, http.StatusConflict, map[string]string{"code": "6", "message": "already exists"})
	})
	_, err := client.CreateOrganization(context.Background(), "Acme Red Team")
	if !errors.Is(err, idp.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1: no lookup follows a conflict", calls)
	}
}

func TestCreateOrganization_RequiresAName(t *testing.T) {
	client := newOrgClient(t, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	if _, err := client.CreateOrganization(context.Background(), ""); err == nil {
		t.Fatal("an empty name must be refused before any request")
	}
}

func TestDeleteOrganization_DeletesAndTreatsAbsentAsSuccess(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound} {
		var gotMethod, gotPath string
		client := newOrgClient(t, func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			jsonResp(w, status, map[string]string{})
		})
		if err := client.DeleteOrganization(context.Background(), "org-9"); err != nil {
			t.Fatalf("status %d: DeleteOrganization: %v", status, err)
		}
		if gotMethod != http.MethodDelete || gotPath != "/v2/organizations/org-9" {
			t.Errorf("%s %s, want DELETE /v2/organizations/org-9", gotMethod, gotPath)
		}
	}
}

func TestDeleteOrganization_RefusesThePlatformOrg(t *testing.T) {
	called := false
	client := newOrgClient(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		jsonResp(w, http.StatusOK, map[string]string{})
	})
	// testConfig names org-123 as the client's own org.
	err := client.DeleteOrganization(context.Background(), "org-123")
	if !errors.Is(err, idp.ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
	if called {
		t.Fatal("the platform org delete reached Zitadel")
	}
}

func TestOrgOfUser_ReadsTheResourceOwner(t *testing.T) {
	client := newOrgClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/users/user-7" {
			http.NotFound(w, r)
			return
		}
		jsonResp(w, http.StatusOK, map[string]interface{}{"details": map[string]string{"resourceOwner": "org-tenant"}})
	})
	org, err := client.OrgOfUser(context.Background(), "user-7")
	if err != nil {
		t.Fatalf("OrgOfUser: %v", err)
	}
	if org != "org-tenant" {
		t.Errorf("org = %q, want org-tenant", org)
	}
}

// A user-state call with no org names the org that owns the user, not the
// platform org: the owner of a self-serve tenant lives in the tenant org,
// and the v1 Management calls select the org by header.
func TestHumanUserState_NoOrgLooksTheOwningOrgUp(t *testing.T) {
	var gotOrg string
	client := newOrgClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/users/user-7":
			jsonResp(w, http.StatusOK, map[string]interface{}{"details": map[string]string{"resourceOwner": "org-tenant"}})
		case strings.HasPrefix(r.URL.Path, "/management/v1/users/user-7/"):
			gotOrg = r.Header.Get("x-zitadel-orgid")
			jsonResp(w, http.StatusOK, map[string]string{})
		default:
			http.NotFound(w, r)
		}
	})
	if err := client.ReactivateHumanUser(context.Background(), idp.HumanUserStateRequest{UserID: "user-7"}); err != nil {
		t.Fatalf("ReactivateHumanUser: %v", err)
	}
	if gotOrg != "org-tenant" {
		t.Errorf("org header = %q, want the org that owns the user", gotOrg)
	}
}
