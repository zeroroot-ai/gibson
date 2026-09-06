// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// fakeFinisher records the state + code it received and returns a canned
// outcome, standing in for the ConnectorAuthService.
type fakeFinisher struct {
	gotState string
	gotCode  string
	err      error
}

func (f *fakeFinisher) FinishAuthorization(_ context.Context, state, code, _ string) (*tenantv1.GetConnectorAuthStatusResponse, error) {
	f.gotState = state
	f.gotCode = code
	if f.err != nil {
		return nil, f.err
	}
	return &tenantv1.GetConnectorAuthStatusResponse{
		State: tenantv1.ConnectorAuthState_CONNECTOR_AUTH_STATE_AUTHORIZED,
	}, nil
}

func TestConnectorOAuthCallback_CompletesAndShowsSuccess(t *testing.T) {
	f := &fakeFinisher{}
	h := connectorOAuthCallbackHandler(f, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/connectors/oauth/callback?code=the-code&state=st-1", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if f.gotState != "st-1" || f.gotCode != "the-code" {
		t.Errorf("finisher got state=%q code=%q", f.gotState, f.gotCode)
	}
	if !strings.Contains(rec.Body.String(), "Authorized") {
		t.Errorf("body = %q, want the success page", rec.Body.String())
	}
}

func TestConnectorOAuthCallback_MissingCodeIsRejected(t *testing.T) {
	f := &fakeFinisher{}
	h := connectorOAuthCallbackHandler(f, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/connectors/oauth/callback?state=st-1", http.NoBody))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if f.gotCode != "" {
		t.Error("the finisher must not be called without a code")
	}
}

func TestConnectorOAuthCallback_VendorErrorShowsAPlainPage(t *testing.T) {
	f := &fakeFinisher{}
	h := connectorOAuthCallbackHandler(f, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/connectors/oauth/callback?error=access_denied", http.NoBody))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if f.gotState != "" {
		t.Error("a vendor error must not reach the finisher")
	}
}

func TestConnectorOAuthCallback_FinishFailureShowsAPlainPage(t *testing.T) {
	f := &fakeFinisher{err: status.Error(codes.PermissionDenied, "unknown or expired authorization state")}
	h := connectorOAuthCallbackHandler(f, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/connectors/oauth/callback?code=c&state=s", http.NoBody))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// The daemon's internal error must not reach the browser verbatim.
	if strings.Contains(rec.Body.String(), "expired authorization state") {
		t.Errorf("callback leaked the internal error: %q", rec.Body.String())
	}
}
