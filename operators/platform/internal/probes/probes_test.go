package probes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestZitadelProbe_Check verifies the probe GETs <Address>/debug/ready and
// maps the status correctly. The Address is the in-cluster Zitadel service —
// see the type doc (platform-operator#76): probing the external OIDC issuer
// pins the operator at 0/1 because that origin is unreachable in-cluster.
func TestZitadelProbe_Check(t *testing.T) {
	t.Run("ready returns 200 → nil", func(t *testing.T) {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()

		p := &ZitadelProbe{Address: srv.URL}
		if err := p.Check(context.Background()); err != nil {
			t.Fatalf("Check() = %v, want nil", err)
		}
		if gotPath != "/debug/ready" {
			t.Errorf("probed path = %q, want /debug/ready", gotPath)
		}
	})

	t.Run("non-200 → error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		p := &ZitadelProbe{Address: srv.URL}
		if err := p.Check(context.Background()); err == nil {
			t.Fatal("Check() = nil, want error for 503")
		}
	})

	t.Run("unreachable → error", func(t *testing.T) {
		p := &ZitadelProbe{Address: "http://127.0.0.1:0"}
		if err := p.Check(context.Background()); err == nil {
			t.Fatal("Check() = nil, want error for unreachable address")
		}
	})
}
