// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// admin_user_state_test.go — the sign-in-state changes the admin-approval
// registration rung runs on (ADR-0006, gibson#22).
//
// The rung's safety rests on one claim: a registered account cannot be used
// until an administrator approves it. That claim is only as good as these
// three calls, so each one is pinned to the endpoint it must hit and to the
// idempotence its callers assume.
package zitadel_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
)

func newStateClient(t *testing.T, handler http.HandlerFunc) *zitadel.Client {
	t.Helper()
	cfg := setupUsersServer(t, handler)
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { closeClient(t, client) })
	return client
}

// Deactivation and reactivation hit the Management verbs, and carry the org
// the caller named rather than the client's default.
func TestHumanUserState_HitsTheManagementVerbs(t *testing.T) {
	cases := []struct {
		name string
		path string
		call func(*zitadel.Client) error
	}{
		{
			"deactivate", "/management/v1/users/user-1/_deactivate",
			func(c *zitadel.Client) error {
				return c.DeactivateHumanUser(context.Background(),
					idp.HumanUserStateRequest{UserID: "user-1", OrgID: "tenant-org"})
			},
		},
		{
			"reactivate", "/management/v1/users/user-1/_reactivate",
			func(c *zitadel.Client) error {
				return c.ReactivateHumanUser(context.Background(),
					idp.HumanUserStateRequest{UserID: "user-1", OrgID: "tenant-org"})
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotPath, gotOrg, gotMethod string
			client := newStateClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotOrg, gotMethod = r.URL.Path, r.Header.Get("x-zitadel-orgid"), r.Method
				jsonResp(w, http.StatusOK, map[string]string{})
			})

			if err := c.call(client); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if gotMethod != http.MethodPost || gotPath != c.path {
				t.Errorf("%s %s, want POST %s", gotMethod, gotPath, c.path)
			}
			if gotOrg != "tenant-org" {
				t.Errorf("org header = %q, want the org the caller named", gotOrg)
			}
		})
	}
}

// A user already in the requested state is the outcome the caller wanted, so
// the precondition failure the identity provider answers with is success. The
// approval path calls these on every decision and must not fail on a repeat.
func TestHumanUserState_AlreadyInTheRequestedStateIsSuccess(t *testing.T) {
	client := newStateClient(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusPreconditionFailed, "FailedPrecondition", "user is already inactive")
	})

	if err := client.DeactivateHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err != nil {
		t.Errorf("deactivating an already-inactive user must succeed, got: %v", err)
	}
	if err := client.ReactivateHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err != nil {
		t.Errorf("reactivating an already-active user must succeed, got: %v", err)
	}
}

// Any other refusal is an error. A deactivation that did not happen must never
// read as one that did.
func TestHumanUserState_OtherFailuresAreErrors(t *testing.T) {
	client := newStateClient(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusInternalServerError, "Internal", "boom")
	})

	if err := client.DeactivateHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err == nil {
		t.Error("a refused deactivation must be an error")
	}
	if err := client.ReactivateHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err == nil {
		t.Error("a refused reactivation must be an error")
	}
}

// A missing user id is caught before any request leaves.
func TestHumanUserState_RequiresAUserID(t *testing.T) {
	client := newStateClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request may be sent for an empty user id, got %s", r.URL.Path)
		jsonResp(w, http.StatusOK, map[string]string{})
	})

	for name, err := range map[string]error{
		"deactivate": client.DeactivateHumanUser(context.Background(), idp.HumanUserStateRequest{}),
		"reactivate": client.ReactivateHumanUser(context.Background(), idp.HumanUserStateRequest{}),
		"delete":     client.DeleteHumanUser(context.Background(), idp.HumanUserStateRequest{}),
	} {
		if !errors.Is(err, idp.ErrUpstream) {
			t.Errorf("%s with no user id: error = %v, want ErrUpstream", name, err)
		}
	}
}

// Deleting the account of a registration that could not be recorded is the
// rollback, so an absent user is success: the caller's intent, that this
// account cannot be used, already holds.
func TestDeleteHumanUser_AbsentUserIsSuccess(t *testing.T) {
	client := newStateClient(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusNotFound, "NotFound", "user not found")
	})

	if err := client.DeleteHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err != nil {
		t.Errorf("deleting an absent user must succeed, got: %v", err)
	}
}

func TestDeleteHumanUser_HitsTheDeleteEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	client := newStateClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		jsonResp(w, http.StatusOK, map[string]string{})
	})

	if err := client.DeleteHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err != nil {
		t.Fatalf("DeleteHumanUser: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/management/v1/users/user-1" {
		t.Errorf("%s %s, want DELETE /management/v1/users/user-1", gotMethod, gotPath)
	}
}

// A delete the identity provider refuses for any other reason is an error: an
// account that stayed usable must not read as removed.
func TestDeleteHumanUser_OtherFailuresAreErrors(t *testing.T) {
	client := newStateClient(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusInternalServerError, "Internal", "boom")
	})

	if err := client.DeleteHumanUser(context.Background(),
		idp.HumanUserStateRequest{UserID: "user-1"}); err == nil {
		t.Error("a refused delete must be an error")
	}
}
