// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// setupSessionServer stands up an httptest server that serves OIDC discovery +
// the OAuth2 token endpoint (so zitadel.New succeeds) and routes the Session v2
// search/delete calls to the provided handler.
func setupSessionServer(t *testing.T, sessionHandler http.HandlerFunc) zitadel.Config {
	t.Helper()
	srv := zitadelconntest.New(t, "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/sessions") {
			sessionHandler(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	return testConfig(t, srv)
}

func TestListUserSessions_MapsMetadata(t *testing.T) {
	cfg := setupSessionServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/sessions/search") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"sessions":[
			{"id":"s1","creationDate":"2026-06-01T10:00:00Z","changeDate":"2026-06-08T09:30:00Z",
			 "userAgent":{"ip":"203.0.113.7","description":"Chrome on macOS"}},
			{"id":"s2","creationDate":"2026-06-05T12:00:00Z","changeDate":"2026-06-05T12:00:00Z",
			 "userAgent":{"ip":"198.51.100.4","description":"Firefox on Linux"}}
		]}`))
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	got, err := client.ListUserSessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != "s1" || got[0].IP != "203.0.113.7" || got[0].Browser != "Chrome on macOS" {
		t.Errorf("session[0] = %+v", got[0])
	}
	if got[0].CreatedAt.IsZero() || got[0].LastActiveAt.IsZero() {
		t.Errorf("session[0] timestamps not parsed: %+v", got[0])
	}
	if !got[0].LastActiveAt.After(got[0].CreatedAt) {
		t.Errorf("expected last_active after created; got created=%v last=%v", got[0].CreatedAt, got[0].LastActiveAt)
	}
}

func TestListUserSessions_Empty(t *testing.T) {
	cfg := setupSessionServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[]}`))
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	got, err := client.ListUserSessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

func TestListUserSessions_MissingUserAgent(t *testing.T) {
	// A session without a userAgent block must yield an entry with empty
	// ip/browser, not a dropped row or an error.
	cfg := setupSessionServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessions":[{"id":"s9","creationDate":"2026-06-01T10:00:00Z"}]}`))
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	got, err := client.ListUserSessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(got) != 1 || got[0].ID != "s9" {
		t.Fatalf("got %+v, want one session s9", got)
	}
	if got[0].IP != "" || got[0].Browser != "" {
		t.Errorf("expected empty ip/browser, got %+v", got[0])
	}
	if !got[0].LastActiveAt.IsZero() {
		t.Errorf("expected zero last_active (no changeDate), got %v", got[0].LastActiveAt)
	}
}

func TestRevokeSession_DeletesByID(t *testing.T) {
	var deletedPath string
	cfg := setupSessionServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if err := client.RevokeSession(context.Background(), "s1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if !strings.HasSuffix(deletedPath, "/v2/sessions/s1") {
		t.Errorf("deleted path = %q, want .../v2/sessions/s1", deletedPath)
	}
}

func TestRevokeSession_NotFoundIsIdempotent(t *testing.T) {
	cfg := setupSessionServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer client.Close()

	if err := client.RevokeSession(context.Background(), "gone"); err != nil {
		t.Errorf("RevokeSession on missing session should be nil, got %v", err)
	}
}
