// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"), "test-v1")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewSigner_RefusesAShortKEK(t *testing.T) {
	if _, err := NewSigner([]byte("short"), "x"); err == nil {
		t.Fatal("want an error for a short KEK")
	}
}

func TestNewRandomSigner_SignsAndChecks(t *testing.T) {
	s, err := NewRandomSigner()
	if err != nil {
		t.Fatal(err)
	}
	scope := []string{"acme", "List"}
	got, has, err := s.After(scope, s.Token(scope, "k1"))
	if err != nil || !has || got != "k1" {
		t.Fatalf("After = %q, %v, %v", got, has, err)
	}
}

func TestSigner_EmptyTokenIsTheFirstPage(t *testing.T) {
	_, has, err := testSigner(t).After([]string{"a"}, "")
	if err != nil || has {
		t.Fatalf("After(empty) = %v, %v; want false, nil", has, err)
	}
}

func TestSigner_EmptyKeyRoundTrips(t *testing.T) {
	s := testSigner(t)
	scope := []string{"acme", "List"}
	key, has, err := s.After(scope, s.Token(scope, ""))
	if err != nil || !has || key != "" {
		t.Fatalf("After = %q, %v, %v; want an empty key", key, has, err)
	}
}

func TestSigner_RefusesAnotherScopeAndAnEditedToken(t *testing.T) {
	s := testSigner(t)
	scope := []string{"acme", "List"}
	tok := s.Token(scope, "k1")
	other, _ := NewSigner([]byte("ffffffffffffffffffffffffffffffff"), "test-v1")
	for name, c := range map[string]struct {
		s     *Signer
		scope []string
		tok   string
	}{
		"other tenant": {s, []string{"other", "List"}, tok},
		"other rpc":    {s, []string{"acme", "Other"}, tok},
		"split scope":  {s, []string{"acmeList"}, tok},
		"other key":    {other, scope, tok},
		"no dot":       {s, scope, "abc"},
		"bad base64":   {s, scope, "%%%.%%%"},
		"bad sig":      {s, scope, tok[:len(tok)-1] + "A" + "x"},
		"no prefix":    {s, scope, s.rawToken(scope, "zz")},
	} {
		if _, _, err := c.s.After(c.scope, c.tok); !errors.Is(err, ErrBadToken) {
			t.Errorf("%s: err = %v, want ErrBadToken", name, err)
		}
	}
}

// rawToken signs a payload that lacks the cursor prefix.
func (s *Signer) rawToken(scope []string, payload string) string {
	p := []byte(payload)
	return b64(p) + "." + b64(s.mac(scope, p))
}

func TestSize(t *testing.T) {
	for _, c := range []struct {
		in   int32
		want int
	}{{0, DefaultSize}, {-1, DefaultSize}, {5, 5}, {MaxSize, MaxSize}, {MaxSize + 1, MaxSize}} {
		if got := Size(c.in); got != c.want {
			t.Errorf("Size(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestKeysetPage_WalksEachItemOnce(t *testing.T) {
	var items []int
	for i := 0; i < 7; i++ {
		items = append(items, i*10)
	}
	key := func(n int) string { return strconv.Itoa(1000 + n) }
	var got []int
	after, has := "", false
	for range 10 {
		page, last, more := KeysetPage(items, key, after, has, 3)
		got = append(got, page...)
		if !more {
			break
		}
		after, has = last, true
	}
	if len(got) != len(items) {
		t.Fatalf("got %v, want %v", got, items)
	}
	for i := range items {
		if got[i] != items[i] {
			t.Fatalf("got %v, want %v", got, items)
		}
	}
}

func TestKeysetPage_ExactMultipleHasNoEmptyLastPage(t *testing.T) {
	items := []string{"a", "b", "c", "d"}
	id := func(s string) string { return s }
	page, last, more := KeysetPage(items, id, "", false, 2)
	if len(page) != 2 || !more || last != "b" {
		t.Fatalf("page 1 = %v, %q, %v", page, last, more)
	}
	page, _, more = KeysetPage(items, id, last, true, 2)
	if len(page) != 2 || more {
		t.Fatalf("page 2 = %v, more %v; want the last page", page, more)
	}
}

func TestKeysetPage_CursorPastTheEnd(t *testing.T) {
	page, last, more := KeysetPage([]string{"a"}, func(s string) string { return s }, "z", true, 2)
	if len(page) != 0 || last != "" || more {
		t.Fatalf("got %v, %q, %v", page, last, more)
	}
}

func b64(p []byte) string { return base64.RawURLEncoding.EncodeToString(p) }
