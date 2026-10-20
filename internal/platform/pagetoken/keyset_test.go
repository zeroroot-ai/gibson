// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"), "test")
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
	other, _ := NewSigner([]byte("ffffffffffffffffffffffffffffffff"), "test")
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
	for i := range 7 {
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

func TestKeys_EachListHasItsOwnKey(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	keys, err := NewKeys(kek)
	if err != nil {
		t.Fatal(err)
	}
	a, b := keys.Signer("a"), keys.Signer("b")
	scope := []string{"acme", "List"}
	tok := a.Token(scope, "k1")
	if _, _, err := b.After(scope, tok); !errors.Is(err, ErrBadToken) {
		t.Fatalf("a token of list a opened list b: %v", err)
	}
	if k, _, err := keys.Signer("a").After(scope, tok); err != nil || k != "k1" {
		t.Fatalf("the same list on another replica: %q, %v", k, err)
	}
	direct, err := NewSigner(kek, "a")
	if err != nil {
		t.Fatal(err)
	}
	if k, _, err := direct.After(scope, tok); err != nil || k != "k1" {
		t.Fatalf("NewSigner and Keys.Signer differ: %q, %v", k, err)
	}
	if keyInfo("audit") != "gibson/v1/audit-page-token" {
		t.Fatalf("keyInfo = %q", keyInfo("audit"))
	}
}

func TestNewKeys_RefusesAShortKEK(t *testing.T) {
	if _, err := NewKeys([]byte("short")); err == nil {
		t.Fatal("want an error for a short KEK")
	}
}

func TestKeysetPage_Descending(t *testing.T) {
	items := []int{50, 40, 30, 20, 10}
	key := func(n int) string { return strconv.Itoa(n) }
	numeric := func(a, b string) int {
		x, _ := strconv.Atoi(a)
		y, _ := strconv.Atoi(b)
		return x - y
	}
	var got []int
	after, has := "", false
	for range 10 {
		page, last, more := KeysetPage(items, key, after, has, 2, Descending(), WithCompare(numeric))
		got = append(got, page...)
		if !more {
			break
		}
		after, has = last, true
	}
	if len(got) != 5 || got[0] != 50 || got[4] != 10 {
		t.Fatalf("got %v, want the items once from 50 down to 10", got)
	}
	// A row that arrives with a larger position than the cursor does not move
	// the next page.
	page, _, _ := KeysetPage([]int{99, 50, 40, 30}, key, "40", true, 5, Descending(), WithCompare(numeric))
	if len(page) != 1 || page[0] != 30 {
		t.Fatalf("page after 40 = %v, want [30]", page)
	}
}

// A composite position such as "unix nanos, id" is an opaque string that the
// list compares itself. Here the comparison already puts the newest first, so
// the list needs no Descending.
func TestKeysetPage_CompositePosition(t *testing.T) {
	type row struct {
		ts int64
		id string
	}
	items := []row{{5, "b"}, {5, "a"}, {3, "z"}, {1, "q"}}
	pos := func(r row) string { return strconv.FormatInt(r.ts, 10) + "|" + r.id }
	cmp := func(a, b string) int {
		at, aid, _ := strings.Cut(a, "|")
		bt, bid, _ := strings.Cut(b, "|")
		ai, _ := strconv.ParseInt(at, 10, 64)
		bi, _ := strconv.ParseInt(bt, 10, 64)
		if ai != bi {
			return int(bi - ai) // newest first
		}
		return strings.Compare(bid, aid)
	}
	page, last, more := KeysetPage(items, pos, "", false, 2, WithCompare(cmp))
	if len(page) != 2 || last != "5|a" || !more {
		t.Fatalf("page 1 = %v, %q, %v", page, last, more)
	}
	page, _, more = KeysetPage(items, pos, last, true, 5, WithCompare(cmp))
	if len(page) != 2 || page[0].id != "z" || more {
		t.Fatalf("page 2 = %v, more %v", page, more)
	}
	// The signer carries the composite position, NUL bytes included.
	s := testSigner(t)
	scope := []string{"acme", "ListAudit"}
	got, has, err := s.After(scope, s.Token(scope, "5\x00a|\xff"))
	if err != nil || !has || got != "5\x00a|\xff" {
		t.Fatalf("round trip = %q, %v, %v", got, has, err)
	}
}

func TestCollect(t *testing.T) {
	pages := map[string]struct {
		items []int
		next  string
	}{"": {[]int{1, 2}, "t1"}, "t1": {[]int{3}, "t2"}, "t2": {[]int{4}, ""}}
	fetch := func(_ context.Context, tok string) ([]int, string, error) {
		p := pages[tok]
		return p.items, p.next, nil
	}
	got, err := Collect(context.Background(), 5, fetch)
	if err != nil || len(got) != 4 || got[3] != 4 {
		t.Fatalf("Collect = %v, %v", got, err)
	}
	if _, err := Collect(context.Background(), 2, fetch); !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("Collect with a bound of 2 = %v, want ErrTooManyPages", err)
	}
	// A bound of 0 is the default, which is large enough for 3 pages.
	if got, err := Collect(context.Background(), 0, fetch); err != nil || len(got) != 4 {
		t.Fatalf("Collect with the default bound = %v, %v", got, err)
	}
}

func TestCollect_FetchErrorAndLoopAndCancel(t *testing.T) {
	boom := errors.New("boom")
	if _, err := Collect(context.Background(), 3, func(context.Context, string) ([]int, string, error) {
		return nil, "", boom
	}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, err := Collect(context.Background(), 5, func(context.Context, string) ([]int, string, error) {
		return []int{1}, "same", nil
	}); !errors.Is(err, ErrTokenLoop) {
		t.Fatalf("err = %v, want ErrTokenLoop", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx, 3, func(context.Context, string) ([]int, string, error) {
		return nil, "", nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
