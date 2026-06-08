package api

import (
	"context"
	"testing"

	sessionv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/session/v1"
	"github.com/zeroroot-ai/gibson/internal/idp"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ctxAsUser(sub string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: sub})
}

func TestListMySessions_ReturnsCallersSessions(t *testing.T) {
	fakeidp := &fakeIDPClient{
		sessionsByUser: map[string][]idp.SessionInfo{
			"user-1": {
				{ID: "s1", IP: "203.0.113.7", Browser: "Chrome on macOS"},
				{ID: "s2", IP: "198.51.100.4", Browser: "Firefox"},
			},
			"user-2": {{ID: "other"}},
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)

	resp, err := srv.ListMySessions(ctxAsUser("user-1"), &sessionv1.ListMySessionsRequest{})
	if err != nil {
		t.Fatalf("ListMySessions: %v", err)
	}
	if len(resp.GetSessions()) != 2 {
		t.Fatalf("got %d sessions, want 2 (only the caller's)", len(resp.GetSessions()))
	}
	if resp.GetSessions()[0].GetId() != "s1" || resp.GetSessions()[0].GetBrowser() != "Chrome on macOS" {
		t.Errorf("session[0] = %+v", resp.GetSessions()[0])
	}
}

func TestListMySessions_Unauthenticated(t *testing.T) {
	srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
	_, err := srv.ListMySessions(context.Background(), &sessionv1.ListMySessionsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("got code %v, want Unauthenticated", status.Code(err))
	}
}

func TestRevokeMySession_OwnedSessionRevoked(t *testing.T) {
	fakeidp := &fakeIDPClient{
		sessionsByUser: map[string][]idp.SessionInfo{
			"user-1": {{ID: "s1"}, {ID: "s2"}},
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)

	_, err := srv.RevokeMySession(ctxAsUser("user-1"), &sessionv1.RevokeMySessionRequest{SessionId: "s2"})
	if err != nil {
		t.Fatalf("RevokeMySession: %v", err)
	}
	if len(fakeidp.revokedSessionIDs) != 1 || fakeidp.revokedSessionIDs[0] != "s2" {
		t.Errorf("revokedSessionIDs = %v, want [s2]", fakeidp.revokedSessionIDs)
	}
}

func TestRevokeMySession_NotOwnedIsNotFound(t *testing.T) {
	// "s9" belongs to nobody the caller owns → NotFound, and the IdP delete
	// must never be reached (self-ownership gate).
	fakeidp := &fakeIDPClient{
		sessionsByUser: map[string][]idp.SessionInfo{
			"user-1": {{ID: "s1"}},
			"user-2": {{ID: "s9"}},
		},
	}
	srv := newTestDaemonServer(t).WithIdPAdminClient(fakeidp)

	_, err := srv.RevokeMySession(ctxAsUser("user-1"), &sessionv1.RevokeMySessionRequest{SessionId: "s9"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want NotFound", status.Code(err))
	}
	if len(fakeidp.revokedSessionIDs) != 0 {
		t.Errorf("expected no revoke call for a non-owned session, got %v", fakeidp.revokedSessionIDs)
	}
}

func TestRevokeMySession_RequiresSessionID(t *testing.T) {
	srv := newTestDaemonServer(t).WithIdPAdminClient(&fakeIDPClient{})
	_, err := srv.RevokeMySession(ctxAsUser("user-1"), &sessionv1.RevokeMySessionRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("got code %v, want InvalidArgument", status.Code(err))
	}
}
