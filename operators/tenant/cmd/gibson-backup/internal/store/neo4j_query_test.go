// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// TestNodeCreateQuery proves a label from a backup archive reaches the query
// text only when it is a plain Cypher identifier.
func TestNodeCreateQuery(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		labels []string
		want   string
		unsafe bool
	}{
		{name: "no labels falls back to Node", labels: nil, want: "CREATE (n:Node) SET n = $props"},
		{name: "two labels", labels: []string{"Person", "Admin_2"}, want: "CREATE (n:Person:Admin_2) SET n = $props"},
		{name: "injection in a label", labels: []string{"Node) DETACH DELETE n //"}, unsafe: true},
		{name: "backtick escape", labels: []string{"`Node`"}, unsafe: true},
		{name: "empty label", labels: []string{""}, unsafe: true},
		{name: "leading digit", labels: []string{"1Node"}, unsafe: true},
		{name: "second label unsafe", labels: []string{"Person", "x:y"}, unsafe: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := nodeCreateQuery(nodeRecord{Labels: tc.labels})
			if tc.unsafe {
				if !errors.Is(err, ErrUnsafeCypherIdentifier) {
					t.Fatalf("want ErrUnsafeCypherIdentifier, got query %q err %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("query = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRelCreateQuery proves the endpoint labels and the relationship type are
// each checked, and the fallbacks apply when an endpoint has no label.
func TestRelCreateQuery(t *testing.T) {
	t.Parallel()
	const want = "MATCH (a:Person), (b:Node) WHERE a = $startProps AND b = $endProps CREATE (a)-[r:KNOWS]->(b) SET r = $relProps"
	got, err := relCreateQuery(relRecord{Type: "KNOWS", StartNodeLabels: []string{"Person", "Ignored"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
	for name, rr := range map[string]relRecord{
		"type injection":  {Type: "KNOWS]->(b) DETACH DELETE a //"},
		"empty type":      {Type: ""},
		"start label":     {Type: "KNOWS", StartNodeLabels: []string{"a b"}},
		"end label":       {Type: "KNOWS", EndNodeLabels: []string{"Node)"}},
		"unicode in type": {Type: "KNOWS\u200b"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := relCreateQuery(rr); !errors.Is(err, ErrUnsafeCypherIdentifier) {
				t.Fatalf("want ErrUnsafeCypherIdentifier, got %v", err)
			}
		})
	}
}

// TestStatementsStopBeforeTheDatabase proves an archive with one bad record
// produces no statements at all: nothing partial reaches the session.
func TestStatementsStopBeforeTheDatabase(t *testing.T) {
	t.Parallel()
	good := `{"labels":["Person"],"properties":{"name":"a"}}` + "\n"
	bad := `{"labels":["Person) DETACH DELETE n //"],"properties":{}}` + "\n"

	stmts, err := nodeStatements([]byte(good + "\n" + good))
	if err != nil || len(stmts) != 2 {
		t.Fatalf("two good records: got %d statements, err %v", len(stmts), err)
	}
	if stmts[0].query != "CREATE (n:Person) SET n = $props" || stmts[0].params["props"] == nil {
		t.Fatalf("unexpected statement %+v", stmts[0])
	}
	if stmts, err := nodeStatements([]byte(good + bad)); !errors.Is(err, ErrUnsafeCypherIdentifier) || stmts != nil {
		t.Fatalf("want ErrUnsafeCypherIdentifier and no statements, got %v %v", err, stmts)
	}
	if _, err := nodeStatements([]byte("{not json")); err == nil {
		t.Fatal("want a parse error")
	}

	rel := `{"type":"KNOWS","start_labels":["Person"],"start_props":{"name":"a"},"end_labels":["Person"],"end_props":{"name":"b"},"properties":{"since":1}}` + "\n"
	rs, err := relStatements([]byte(rel))
	if err != nil || len(rs) != 1 {
		t.Fatalf("one rel: got %d statements, err %v", len(rs), err)
	}
	if rs[0].params["relProps"] == nil || rs[0].params["startProps"] == nil || rs[0].params["endProps"] == nil {
		t.Fatalf("rel params incomplete: %+v", rs[0].params)
	}
	badRel := `{"type":"KNOWS]->(b) DETACH DELETE a //"}` + "\n"
	if rs, err := relStatements([]byte(rel + badRel)); !errors.Is(err, ErrUnsafeCypherIdentifier) || rs != nil {
		t.Fatalf("want ErrUnsafeCypherIdentifier and no statements, got %v %v", err, rs)
	}
	if _, err := relStatements([]byte("{not json")); err == nil {
		t.Fatal("want a parse error")
	}
}

// fakeSession records every query ExecuteWrite runs. The embedded interface
// leaves every other method nil: the restore path calls only ExecuteWrite,
// and the transaction calls only Run.
type fakeSession struct {
	neo4j.SessionWithContext
	queries []string
	failOn  string
}

type fakeTx struct {
	neo4j.ManagedTransaction
	s *fakeSession
}

func (s *fakeSession) ExecuteWrite(ctx context.Context, work neo4j.ManagedTransactionWork, _ ...func(*neo4j.TransactionConfig)) (any, error) {
	return work(fakeTx{s: s})
}

func (t fakeTx) Run(_ context.Context, cypher string, _ map[string]any) (neo4j.ResultWithContext, error) {
	t.s.queries = append(t.s.queries, cypher)
	if t.s.failOn != "" && strings.Contains(cypher, t.s.failOn) {
		return nil, errors.New("write refused")
	}
	return nil, nil
}

// TestImportRunsOnlyCheckedStatements drives importNodes and
// importRelationships through the fake session: every query that reaches the
// session is one the builders produced, a bad record runs nothing, and a
// session error stops the import.
func TestImportRunsOnlyCheckedStatements(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	nodes := []byte(`{"labels":["Person"],"properties":{"name":"a"}}` + "\n" + `{"labels":[],"properties":{}}` + "\n")
	rels := []byte(`{"type":"KNOWS","start_labels":["Person"],"end_labels":["Person"]}` + "\n")

	s := &fakeSession{}
	if err := importNodes(ctx, s, nodes); err != nil {
		t.Fatalf("importNodes: %v", err)
	}
	if err := importRelationships(ctx, s, rels); err != nil {
		t.Fatalf("importRelationships: %v", err)
	}
	want := []string{
		"CREATE (n:Person) SET n = $props",
		"CREATE (n:Node) SET n = $props",
		"MATCH (a:Person), (b:Person) WHERE a = $startProps AND b = $endProps CREATE (a)-[r:KNOWS]->(b) SET r = $relProps",
	}
	if strings.Join(s.queries, "|") != strings.Join(want, "|") {
		t.Fatalf("queries = %q", s.queries)
	}

	bad := &fakeSession{}
	if err := importNodes(ctx, bad, []byte(`{"labels":["Node) DETACH DELETE n //"]}`)); !errors.Is(err, ErrUnsafeCypherIdentifier) {
		t.Fatalf("want ErrUnsafeCypherIdentifier, got %v", err)
	}
	if err := importRelationships(ctx, bad, []byte(`{"type":"x y"}`)); !errors.Is(err, ErrUnsafeCypherIdentifier) {
		t.Fatalf("want ErrUnsafeCypherIdentifier, got %v", err)
	}
	if len(bad.queries) != 0 {
		t.Fatalf("a bad archive ran %d queries", len(bad.queries))
	}

	failing := &fakeSession{failOn: "Node"}
	if err := importNodes(ctx, failing, nodes); err == nil || err.Error() != "write refused" {
		t.Fatalf("want the session error, got %v", err)
	}
	if len(failing.queries) != 2 {
		t.Fatalf("import continued past the failed write: %q", failing.queries)
	}
	if err := importRelationships(ctx, &fakeSession{failOn: "KNOWS"}, rels); err == nil {
		t.Fatal("want the session error from importRelationships")
	}
}
