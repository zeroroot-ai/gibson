// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"bytes"
	"errors"
	"testing"
)

func testRequestSigner(t *testing.T) *Signer {
	t.Helper()
	keys, err := NewKeys(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Signer("test-list")
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestNewRequest_RefusesNoSignerAndABadToken(t *testing.T) {
	if _, err := NewRequest(nil, []string{"acme"}, 5, ""); !errors.Is(err, ErrNoSigner) {
		t.Errorf("no signer: err = %v, want ErrNoSigner", err)
	}
	if _, err := NewRequest(testRequestSigner(t), []string{"acme"}, 5, "forged.token"); !errors.Is(err, ErrBadToken) {
		t.Errorf("forged: err = %v, want ErrBadToken", err)
	}
}

// A walk with rows between the pages gives each first row once, and the token
// of one scope does not open another.
func TestPage_WalkWithRowsBetweenPages(t *testing.T) {
	signer := testRequestSigner(t)
	scope := []string{"acme", "test-list"}
	key := func(s string) string { return s }
	items := []string{"b", "d", "f", "h", "j"}
	seen := map[string]int{}
	token := ""
	var first string
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("the walk did not end")
		}
		r, err := NewRequest(signer, scope, 2, token)
		if err != nil {
			t.Fatal(err)
		}
		page, next := Page(r, items, key)
		for _, v := range page {
			seen[v]++
		}
		if pages == 0 {
			first = next
		}
		items = append(items, "a"+string(rune('0'+pages)), "e"+string(rune('0'+pages)))
		if next == "" {
			break
		}
		token = next
	}
	for _, v := range []string{"b", "d", "f", "h", "j"} {
		if seen[v] != 1 {
			t.Errorf("%q seen %d times, want 1", v, seen[v])
		}
	}
	for v, n := range seen {
		if n != 1 {
			t.Errorf("%q seen %d times", v, n)
		}
	}
	if _, err := NewRequest(signer, []string{"globex", "test-list"}, 2, first); !errors.Is(err, ErrBadToken) {
		t.Errorf("cross-tenant token: err = %v, want ErrBadToken", err)
	}
}

func TestRequest_AccessorsAndTheLastPage(t *testing.T) {
	r, err := NewRequest(testRequestSigner(t), []string{"acme"}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, has := r.After(); has || r.Limit() != DefaultSize {
		t.Errorf("first page: hasAfter %v, limit %d", has, r.Limit())
	}
	if tok := r.Token("k", false); tok != "" {
		t.Errorf("the last page has token %q", tok)
	}
	next, err := NewRequest(testRequestSigner(t), []string{"acme"}, 3, r.Token("k", true))
	if err != nil {
		t.Fatal(err)
	}
	if pos, has := next.After(); !has || pos != "k" {
		t.Errorf("After = %q, %v", pos, has)
	}
}
