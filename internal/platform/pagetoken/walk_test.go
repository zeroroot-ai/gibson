// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"context"
	"errors"
	"testing"
)

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
