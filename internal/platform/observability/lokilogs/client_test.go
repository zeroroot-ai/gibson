package lokilogs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClient_MissionQuery_TenantScoping verifies that the daemon-derived tenant
// is folded into BOTH the LogQL tenant_id label selector and the X-Scope-OrgID
// header is the fixed "gibson" org — the tenant scope is never client-supplied.
func TestClient_MissionQuery_TenantScoping(t *testing.T) {
	var gotQuery, gotOrg string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		gotOrg = r.Header.Get("X-Scope-OrgID")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[` +
			`{"stream":{"tenant_id":"acme"},"values":[["1700000000000000000","hello mission m1"]]}]}}`))
	}))
	defer ts.Close()

	c, err := NewClient(Config{BaseURL: ts.URL}, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	entries, err := c.QueryMissionLogs(context.Background(), MissionQuery{TenantID: "acme", MissionID: "m1"})
	if err != nil {
		t.Fatalf("QueryMissionLogs: %v", err)
	}
	if len(entries) != 1 || entries[0].Line != "hello mission m1" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if !strings.Contains(gotQuery, `tenant_id="acme"`) {
		t.Fatalf("query missing tenant_id label: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, `m1`) {
		t.Fatalf("query missing mission filter: %q", gotQuery)
	}
	if gotOrg != "gibson" {
		t.Fatalf("X-Scope-OrgID = %q, want gibson", gotOrg)
	}
}

// TestClient_DaemonQuery_LevelFilter verifies level/mission filters appear in
// the LogQL and tenant scoping holds.
func TestClient_DaemonQuery_LevelFilter(t *testing.T) {
	var gotQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer ts.Close()

	c, _ := NewClient(Config{BaseURL: ts.URL}, nil)
	if _, err := c.QueryDaemonLogs(context.Background(), DaemonQuery{TenantID: "beta", Level: "ERROR", MissionID: "mX"}); err != nil {
		t.Fatalf("QueryDaemonLogs: %v", err)
	}
	for _, want := range []string{`tenant_id="beta"`, `ERROR`, `mX`} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

// TestClient_Unavailable maps a non-200 to ErrLokiUnavailable.
func TestClient_Unavailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	c, _ := NewClient(Config{BaseURL: ts.URL}, nil)
	if _, err := c.QueryMissionLogs(context.Background(), MissionQuery{TenantID: "acme", MissionID: "m1"}); err == nil {
		t.Fatal("expected ErrLokiUnavailable, got nil")
	}
}

func TestNewClient_RequiresBaseURL(t *testing.T) {
	if _, err := NewClient(Config{}, nil); err == nil {
		t.Fatal("expected error for empty BaseURL")
	}
}
