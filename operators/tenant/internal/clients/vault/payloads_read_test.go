package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

// The KV v2 read envelope, the way OpenBao answers a GET on
// /v1/secret/data/<path>: the blob writeInfraSecret stored under "value".
func kvEnvelope(t *testing.T, payload any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{"data": map[string]any{"data": map[string]any{
		"value": base64.StdEncoding.EncodeToString(raw),
	}}}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReadInfraNeo4jCredentials(t *testing.T) {
	want := pdataplane.Neo4jCredentials{BoltURI: "bolt://acme-neo4j.tenant-acme.svc.cluster.local:7687", Username: "neo4j", Password: "Pk3ep5thi5"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/infra/neo4j", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.Header.Get("X-Vault-Namespace") {
		case "tenant-acme", "tenant-acme/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(kvEnvelope(t, want))
		case "tenant-broken", "tenant-broken/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"value":"not base64!"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := New(Config{Address: srv.URL, AdminToken: "t", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}

	got, found, err := c.ReadInfraNeo4jCredentials(context.Background(), "acme")
	if err != nil || !found {
		t.Fatalf("restored store: found=%v err=%v", found, err)
	}
	if got != want {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}

	// A tenant provisioned for the first time: nothing at the path is not an error.
	_, found, err = c.ReadInfraNeo4jCredentials(context.Background(), "fresh")
	if err != nil || found {
		t.Fatalf("empty path: found=%v err=%v, want found=false err=nil", found, err)
	}

	// A blob that is not what writeInfraSecret produces is an error, never a
	// silent "not found" that would make the operator mint a new password
	// over a store that still holds the old one.
	if _, _, err = c.ReadInfraNeo4jCredentials(context.Background(), "broken"); err == nil {
		t.Fatal("a blob that is not base64 JSON must be an error")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected error class")
	}
}
