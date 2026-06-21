package dataplane_test

import (
	"encoding/json"
	"testing"

	"github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
)

func TestPostgresCredentials_RoundTrip(t *testing.T) {
	want := dataplane.PostgresCredentials{
		Host:     "gibson-tenant-postgresql",
		Port:     5432,
		Database: "tenant_acme",
		Role:     "tenant_acme_app",
		Password: "deadbeef0000000000000000deadbeef",
		DSN:      "postgres://tenant_acme_app:deadbeef0000000000000000deadbeef@gibson-tenant-postgresql:5432/tenant_acme?sslmode=require",
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got dataplane.PostgresCredentials
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestNeo4jCredentials_RoundTrip(t *testing.T) {
	want := dataplane.Neo4jCredentials{
		BoltURI:  "bolt://tenant-acme-neo4j.gibson.svc.cluster.local:7687",
		Username: "neo4j",
		Password: "rDpkZ0JM5n8XKM/yRxZMjEFlFBfHgvKlRJoKDpZ+5gI=",
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got dataplane.Neo4jCredentials
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestRedisCredentials_RoundTrip(t *testing.T) {
	want := dataplane.RedisCredentials{
		Addr:     "gibson-redis-stack:6379",
		DBIndex:  5,
		Password: "",
	}
	b, _ := json.Marshal(want)
	var got dataplane.RedisCredentials
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

func TestVectorCredentials_RoundTrip(t *testing.T) {
	want := dataplane.VectorCredentials{
		IndexName: "vector_idx:tenant_acme",
	}
	b, _ := json.Marshal(want)
	if !contains(string(b), `"index_name"`) {
		t.Errorf("marshal output missing index_name field: %s", string(b))
	}
	var got dataplane.VectorCredentials
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// Field-name guard: the JSON tags must match the design.md schema
// byte-for-byte. A regression here breaks every existing tenant.
func TestJSONFieldNames(t *testing.T) {
	checks := []struct {
		name   string
		v      interface{}
		expect string
	}{
		{"PostgresCredentials", dataplane.PostgresCredentials{Host: "h"}, `"host":"h"`},
		{"Neo4jCredentials", dataplane.Neo4jCredentials{BoltURI: "u"}, `"bolt_uri":"u"`},
		{"RedisCredentials", dataplane.RedisCredentials{DBIndex: 7}, `"db_index":7`},
		{"VectorCredentials", dataplane.VectorCredentials{IndexName: "i"}, `"index_name":"i"`},
	}
	for _, c := range checks {
		b, _ := json.Marshal(c.v)
		if !contains(string(b), c.expect) {
			t.Errorf("%s: marshal %s missing %q", c.name, string(b), c.expect)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > len(sub) && (containsIdx(s, sub))))
}
func containsIdx(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
