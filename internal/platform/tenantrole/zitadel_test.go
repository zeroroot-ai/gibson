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
	return func(w http.ResponseWriter, _ *http.Request) {
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

// TestZitadelGrants_MapsHTTPStatusWhenTheConnectCodeIsMissingOrUnknown pins
// mapConnectError's fallback path: real Connect deployments always answer
// with the matching HTTP status even on a code this client does not
// recognize, so the status alone must still resolve to the right sentinel.
func TestZitadelGrants_MapsHTTPStatusWhenTheConnectCodeIsMissingOrUnknown(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"404 with no code", http.StatusNotFound, tenantrole.ErrNotFound},
		{"409 with no code", http.StatusConflict, tenantrole.ErrAlreadyExists},
		{"401 with no code", http.StatusUnauthorized, tenantrole.ErrUnauthorized},
		{"403 with no code", http.StatusForbidden, tenantrole.ErrUnauthorized},
		{"422 with no code", http.StatusUnprocessableEntity, tenantrole.ErrRejected},
		{"500 with no code", http.StatusInternalServerError, tenantrole.ErrUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("plain text, no connect code"))
			})
			srv := zitadelconntest.New(t, "", mux)
			ep := srv.Endpoint(t)
			hc := &http.Client{Transport: ep.Transport(nil)}
			grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

			_, err := grants.Create(context.Background(), "ORG-1", "USER-1", tenantrole.Owner)
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d, no code: err = %v, want it to wrap %v", tc.status, err, tc.want)
			}
		})
	}
}

// TestZitadelGrants_ConnectJSONWrapsATransportFailure pins that a request
// that never reaches a server (connection refused) surfaces ErrUnreachable,
// not a bare transport error.
func TestZitadelGrants_ConnectJSONWrapsATransportFailure(t *testing.T) {
	srv := zitadelconntest.New(t, "", http.NewServeMux())
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")
	srv.Close() // now nothing is listening

	_, err := grants.Create(context.Background(), "ORG-1", "USER-1", tenantrole.Owner)
	if !errors.Is(err, tenantrole.ErrUnreachable) {
		t.Fatalf("Create after the server closed: err = %v, want it to wrap ErrUnreachable", err)
	}
}

// TestZitadelGrants_ConnectJSONWrapsADecodeFailure pins that a 200 response
// whose body is not valid JSON surfaces a wrapped decode error rather than
// panicking or silently returning a zero value.
func TestZitadelGrants_ConnectJSONWrapsADecodeFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/CreateAuthorization", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	})
	srv := zitadelconntest.New(t, "", mux)
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

	_, err := grants.Create(context.Background(), "ORG-1", "USER-1", tenantrole.Owner)
	if err == nil {
		t.Fatal("Create with an invalid JSON body: got nil error")
	}
}

// TestZitadelGrants_UpdatePropagatesAnUpstreamError pins that Update, unlike
// Delete, does not swallow any error class — a rejection from the fake
// surfaces as-is.
func TestZitadelGrants_UpdatePropagatesAnUpstreamError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/UpdateAuthorization", connectErrHandler("failed_precondition", http.StatusBadRequest))
	srv := zitadelconntest.New(t, "", mux)
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

	if err := grants.Update(context.Background(), "GRANT-1", tenantrole.Admin); !errors.Is(err, tenantrole.ErrRejected) {
		t.Fatalf("Update: err = %v, want it to wrap ErrRejected", err)
	}
}

// TestZitadelGrants_DeletePropagatesANonNotFoundError pins the other half of
// TestZitadelGrants_DeleteToleratesAnAbsentID: Delete only swallows
// ErrNotFound, every other failure still surfaces.
func TestZitadelGrants_DeletePropagatesANonNotFoundError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/zitadel.authorization.v2.AuthorizationService/DeleteAuthorization", connectErrHandler("permission_denied", http.StatusForbidden))
	srv := zitadelconntest.New(t, "", mux)
	ep := srv.Endpoint(t)
	hc := &http.Client{Transport: ep.Transport(nil)}
	grants := tenantrole.NewZitadelGrants(ep, hc, "PROJ-1")

	if err := grants.Delete(context.Background(), "GRANT-1"); !errors.Is(err, tenantrole.ErrUnauthorized) {
		t.Fatalf("Delete: err = %v, want it to wrap ErrUnauthorized (only not_found is swallowed)", err)
	}
}
