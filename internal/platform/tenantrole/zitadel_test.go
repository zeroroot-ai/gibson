// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// TestZitadelGrants_EveryRequestCarriesTheInstanceHeader pins that a Grants
// built without the instance-header transport is refused by the fake for
// every call: List, Create, Update and Delete alike. NewZitadelGrants itself
// sets no header — it is the caller's http.Client that must carry it
// (ADR-0092) — so this also documents that contract.
func TestZitadelGrants_EveryRequestCarriesTheInstanceHeader(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	ep := srv.Endpoint(t)

	plain := &http.Client{} // no instance-header transport
	grants := tenantrole.NewZitadelGrants(ep, plain, "PROJ-1")

	if _, err := grants.List(context.Background(), "ORG-1", nil); err == nil {
		t.Fatal("List with no instance header: expected an error")
	}
	if srv.Refused() == 0 {
		t.Fatal("the fake accepted a request that named no instance")
	}
}

func TestZitadelGrants_EveryRequestSucceedsWithTheInstanceHeader(t *testing.T) {
	id := zitadelconntest.NewIdentity()
	srv := zitadelconntest.New(t, "", id.Handler())
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}

	platformOrg := id.AddOrg("platform")
	project := id.AddProject(platformOrg, "gibson")
	tenantOrg := id.AddOrg("tenant-1")
	postJSON(t, hc, ep, "/zitadel.project.v2.ProjectService/AddProjectRole", map[string]any{
		"projectId": project, "roleKey": "owner", "displayName": "Owner",
	})
	postJSON(t, hc, ep, "/zitadel.project.v2.ProjectService/CreateProjectGrant", map[string]any{
		"projectId": project, "grantedOrganizationId": tenantOrg, "roleKeys": []string{"owner"},
	})
	userID := id.AddUser(tenantOrg, "owner@example.com")

	grants := tenantrole.NewZitadelGrants(ep, hc, project)
	grantID, err := grants.Create(context.Background(), tenantOrg, userID, tenantrole.Owner)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if srv.Refused() != 0 {
		t.Fatalf("Refused = %d, want 0 (every call named the instance)", srv.Refused())
	}
	if err := grants.Update(context.Background(), grantID, tenantrole.Owner); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := grants.Delete(context.Background(), grantID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// --- Connect error code -> sentinel mapping --------------------------------

func connectErrHandler(code string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": "Errors.Test"})
	}
}

func TestZitadelGrants_MapsConnectErrorCodesToSentinels(t *testing.T) {
	cases := []struct {
		code   string
		status int
		want   error
	}{
		{"not_found", http.StatusNotFound, tenantrole.ErrNotFound},
		{"already_exists", http.StatusConflict, tenantrole.ErrAlreadyExists},
		{"failed_precondition", http.StatusBadRequest, tenantrole.ErrRejected},
		{"invalid_argument", http.StatusBadRequest, tenantrole.ErrRejected},
		{"unauthenticated", http.StatusUnauthorized, tenantrole.ErrUnauthorized},
		{"permission_denied", http.StatusForbidden, tenantrole.ErrUnauthorized},
		{"unavailable", http.StatusServiceUnavailable, tenantrole.ErrUnreachable},
		{"deadline_exceeded", http.StatusGatewayTimeout, tenantrole.ErrUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", connectErrHandler(tc.code, tc.status))
			srv := zitadelconntest.New(t, "", mux)
			ep := srv.Endpoint(t)
			hc := &http.Client{Transport: ep.Transport(nil)}
			grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

			_, err := grants.Create(context.Background(), "ORG-1", "USER-1", tenantrole.Owner)
			if !errors.Is(err, tc.want) {
				t.Fatalf("code %q: err = %v, want it to wrap %v", tc.code, err, tc.want)
			}
		})
	}
}

// TestZitadelGrants_DeleteToleratesAnAbsentID pins that Delete does not
// surface ErrNotFound: an absent grant id is success, matching the real
// DeleteAuthorization semantics.
func TestZitadelGrants_DeleteToleratesAnAbsentID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", connectErrHandler("not_found", http.StatusNotFound))
	srv := zitadelconntest.New(t, "", mux)
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

	if err := grants.Delete(context.Background(), "gone"); err != nil {
		t.Fatalf("Delete: %v, want nil (absent id is success)", err)
	}
}

// --- pagination -------------------------------------------------------------

// TestZitadelGrants_ListPages pins that List walks every page: a server
// that returns two authorizations per call and a totalResult of 5 is asked
// three times before List stops.
func TestZitadelGrants_ListPages(t *testing.T) {
	all := make([]map[string]any, 5)
	for i := range all {
		all[i] = map[string]any{
			"id":           fmt.Sprintf("GRANT-%d", i),
			"project":      map[string]string{"id": "PROJ-1", "organizationId": "PLATFORM-ORG"},
			"organization": map[string]string{"id": "ORG-1"},
			"user":         map[string]string{"id": fmt.Sprintf("USER-%d", i), "organizationId": "ORG-1"},
			"state":        "STATE_ACTIVE",
			"roles":        []map[string]string{{"key": "viewer"}},
		}
	}
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/ListAuthorizations", func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			Pagination struct {
				Offset int `json:"offset"`
			} `json:"pagination"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		end := req.Pagination.Offset + 2
		if end > len(all) {
			end = len(all)
		}
		page := all[req.Pagination.Offset:end]
		if page == nil {
			page = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorizations": page,
			"pagination":     map[string]any{"totalResult": len(all)},
		})
	})
	srv := zitadelconntest.New(t, "", mux)
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

	got, err := grants.List(context.Background(), "ORG-1", nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(all) {
		t.Fatalf("List returned %d grants, want %d", len(got), len(all))
	}
	if calls != 3 {
		t.Fatalf("List made %d requests, want 3 (2+2+1 pages)", calls)
	}
}
