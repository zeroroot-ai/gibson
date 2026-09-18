// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package store

import (
	"errors"
	"testing"
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
		"unicode in type": {Type: "KNOWS​"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := relCreateQuery(rr); !errors.Is(err, ErrUnsafeCypherIdentifier) {
				t.Fatalf("want ErrUnsafeCypherIdentifier, got %v", err)
			}
		})
	}
}
