// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconntest_test

import (
	"net/http"
	"testing"
)

// --- AddHumanUser -----------------------------------------------------

func TestIdentity_AddHumanUser_Success(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")

	var resp struct {
		UserID string `json:"userId"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/AddHumanUser", map[string]any{
		"username":     "owner@example.com",
		"organization": map[string]any{"orgId": orgID},
		"profile":      map[string]any{"givenName": "Platform", "familyName": "Owner"},
		"email":        map[string]any{"email": "owner@example.com", "isVerified": true},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if resp.UserID == "" {
		t.Fatal("expected a non-empty userId")
	}
}

func TestIdentity_AddHumanUser_RejectsAPasswordField(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/AddHumanUser", map[string]any{
		"username":     "owner@example.com",
		"organization": map[string]any{"orgId": orgID},
		"password":     map[string]any{"password": "sneaky"},
		"email":        map[string]any{"email": "owner@example.com"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (a password field must be refused, ADR-0093)", status)
	}
}

func TestIdentity_AddHumanUser_EmptyOrgID(t *testing.T) {
	id, e := newFake(t)
	_ = id

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/AddHumanUser", map[string]any{
		"username": "owner@example.com",
		"email":    map[string]any{"email": "owner@example.com"},
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (empty organization.orgId)", status)
	}
}

func TestIdentity_AddHumanUser_UnknownOrg(t *testing.T) {
	id, e := newFake(t)
	_ = id

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/AddHumanUser", map[string]any{
		"username":     "owner@example.com",
		"organization": map[string]any{"orgId": "no-such-org"},
		"email":        map[string]any{"email": "owner@example.com"},
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (unknown org)", status)
	}
}

func TestIdentity_AddHumanUser_AlreadyExists(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	id.AddUser(orgID, "owner@example.com")

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/AddHumanUser", map[string]any{
		"username":     "owner@example.com",
		"organization": map[string]any{"orgId": orgID},
		"email":        map[string]any{"email": "owner@example.com"},
	}, &errBody)
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (duplicate email)", status)
	}
}

// --- ListUsers ----------------------------------------------------------

func TestIdentity_ListUsers_FiltersByEmail(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	want := id.AddUser(orgID, "owner@example.com")
	id.AddUser(orgID, "someone-else@example.com")

	var resp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListUsers", map[string]any{
		"queries": []map[string]any{{"emailQuery": map[string]any{"email": "owner@example.com"}}},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(resp.Result) != 1 || resp.Result[0].UserID != want {
		t.Fatalf("result = %+v, want exactly one match for %s", resp.Result, want)
	}
}

func TestIdentity_ListUsers_NoMatch(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	id.AddUser(orgID, "someone-else@example.com")

	var resp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListUsers", map[string]any{
		"queries": []map[string]any{{"emailQuery": map[string]any{"email": "nobody@example.com"}}},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(resp.Result) != 0 {
		t.Fatalf("result = %+v, want empty", resp.Result)
	}
}

func TestIdentity_ListUsers_NoQueryListsEveryone(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	id.AddUser(orgID, "a@example.com")
	id.AddUser(orgID, "b@example.com")

	var resp struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListUsers", map[string]any{}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if len(resp.Result) != 2 {
		t.Fatalf("result has %d entries, want 2", len(resp.Result))
	}
}

// --- CreateInviteCode -----------------------------------------------------

func TestIdentity_CreateInviteCode_ReturnCode(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var resp struct {
		InviteCode string `json:"inviteCode"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/CreateInviteCode", map[string]any{
		"userId":     userID,
		"returnCode": map[string]any{},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if resp.InviteCode == "" {
		t.Fatal("expected a non-empty inviteCode")
	}
	if got := id.InviteCode(userID); got != resp.InviteCode {
		t.Fatalf("InviteCode() = %q, want %q", got, resp.InviteCode)
	}

	// A second returnCode invalidates (overwrites) the first, matching
	// Zitadel's documented behavior.
	status = post(t, e, "/zitadel.user.v2.UserService/CreateInviteCode", map[string]any{
		"userId":     userID,
		"returnCode": map[string]any{},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if id.InviteCode(userID) == "" {
		t.Fatal("expected a new invite code after a second returnCode call")
	}
}

func TestIdentity_CreateInviteCode_SendCode(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var resp struct {
		InviteCode string `json:"inviteCode"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/CreateInviteCode", map[string]any{
		"userId":   userID,
		"sendCode": map[string]any{"urlTemplate": "https://app.example.com/invite"},
	}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if resp.InviteCode != "" {
		t.Fatalf("inviteCode = %q, want empty on sendCode (real Zitadel emails it, never returns it)", resp.InviteCode)
	}
}

func TestIdentity_CreateInviteCode_UserNotFound(t *testing.T) {
	id, e := newFake(t)
	_ = id

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/CreateInviteCode", map[string]any{
		"userId":     "no-such-user",
		"returnCode": map[string]any{},
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestIdentity_CreateInviteCode_MissingVerification(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/CreateInviteCode", map[string]any{
		"userId": userID,
	}, &errBody)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (neither returnCode nor sendCode set)", status)
	}
}

// --- ListAuthenticationMethodTypes / RemoveTOTP / U2F / Passkeys ---------

func TestIdentity_ListAuthenticationMethodTypes_UserNotFound(t *testing.T) {
	id, e := newFake(t)
	_ = id

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/ListAuthenticationMethodTypes", map[string]any{
		"userId": "no-such-user",
	}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestIdentity_ListAuthenticationMethodTypes_ReportsEveryRegisteredFactor(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var resp struct {
		AuthMethodTypes []string `json:"authMethodTypes"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListAuthenticationMethodTypes", map[string]any{"userId": userID}, &resp)
	if status != http.StatusOK || len(resp.AuthMethodTypes) != 0 {
		t.Fatalf("status=%d types=%v, want 200 and no factors on a fresh user", status, resp.AuthMethodTypes)
	}

	id.AddTOTP(userID)
	id.AddU2F(userID)
	status = post(t, e, "/zitadel.user.v2.UserService/ListAuthenticationMethodTypes", map[string]any{"userId": userID}, &resp)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	want := map[string]bool{"AUTHENTICATION_METHOD_TYPE_TOTP": true, "AUTHENTICATION_METHOD_TYPE_U2F": true}
	if len(resp.AuthMethodTypes) != len(want) {
		t.Fatalf("authMethodTypes = %v, want exactly %v", resp.AuthMethodTypes, want)
	}
	for _, ty := range resp.AuthMethodTypes {
		if !want[ty] {
			t.Fatalf("unexpected authMethodType %q", ty)
		}
	}

	totp, u2fCount, passkeyCount := id.HumanFactors(userID)
	if !totp || u2fCount != 1 || passkeyCount != 0 {
		t.Fatalf("HumanFactors() = (%v, %d, %d), want (true, 1, 0)", totp, u2fCount, passkeyCount)
	}
}

func TestIdentity_RemoveTOTP(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/RemoveTOTP", map[string]any{"userId": userID}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no TOTP registered yet)", status)
	}

	id.AddTOTP(userID)
	status = post(t, e, "/zitadel.user.v2.UserService/RemoveTOTP", map[string]any{"userId": userID}, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	totp, _, _ := id.HumanFactors(userID)
	if totp {
		t.Fatal("TOTP still reports registered after RemoveTOTP")
	}
}

func TestIdentity_ListAndRemoveU2F(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")
	credID := id.AddU2F(userID)

	var listResp struct {
		Result []map[string]string `json:"result"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListU2F", map[string]any{"userId": userID}, &listResp)
	if status != http.StatusOK || len(listResp.Result) != 1 || listResp.Result[0]["u2fId"] != credID {
		t.Fatalf("ListU2F status=%d result=%v, want one entry with id %s", status, listResp.Result, credID)
	}

	status = post(t, e, "/zitadel.user.v2.UserService/RemoveU2F", map[string]any{"userId": userID, "u2fId": credID}, nil)
	if status != http.StatusOK {
		t.Fatalf("RemoveU2F status = %d, want 200", status)
	}
	_, u2fCount, _ := id.HumanFactors(userID)
	if u2fCount != 0 {
		t.Fatalf("u2fCount = %d after removal, want 0", u2fCount)
	}

	// Removing an id that is not present is idempotent, not an error.
	status = post(t, e, "/zitadel.user.v2.UserService/RemoveU2F", map[string]any{"userId": userID, "u2fId": "not-there"}, nil)
	if status != http.StatusOK {
		t.Fatalf("RemoveU2F (already absent) status = %d, want 200", status)
	}
}

func TestIdentity_ListAndRemovePasskeys_Success(t *testing.T) {
	id, e := newFake(t)
	orgID := id.AddOrg("platform")
	userID := id.AddUser(orgID, "owner@example.com")

	var listResp struct {
		Result []map[string]string `json:"result"`
	}
	status := post(t, e, "/zitadel.user.v2.UserService/ListPasskeys", map[string]any{"userId": userID}, &listResp)
	if status != http.StatusOK || len(listResp.Result) != 0 {
		t.Fatalf("ListPasskeys status=%d result=%v, want 200 and empty on a fresh user", status, listResp.Result)
	}

	// RemovePasskey on a user with none registered is idempotent, not an error.
	status = post(t, e, "/zitadel.user.v2.UserService/RemovePasskey", map[string]any{"userId": userID, "passkeyId": "not-there"}, nil)
	if status != http.StatusOK {
		t.Fatalf("RemovePasskey status = %d, want 200", status)
	}
}

func TestIdentity_ListAndRemovePasskeys_UserNotFound(t *testing.T) {
	id, e := newFake(t)
	_ = id

	var errBody map[string]any
	status := post(t, e, "/zitadel.user.v2.UserService/ListPasskeys", map[string]any{"userId": "no-such-user"}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("ListPasskeys status = %d, want 404", status)
	}
	status = post(t, e, "/zitadel.user.v2.UserService/RemovePasskey", map[string]any{"userId": "no-such-user", "passkeyId": "x"}, &errBody)
	if status != http.StatusNotFound {
		t.Fatalf("RemovePasskey status = %d, want 404", status)
	}
}
