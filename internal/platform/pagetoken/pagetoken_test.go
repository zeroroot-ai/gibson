// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pagetoken

import (
	"errors"
	"math"
	"testing"
)

func TestWindow_SizeDefaultsAndCaps(t *testing.T) {
	for _, c := range []struct {
		size int32
		want int
	}{{0, DefaultSize}, {-3, DefaultSize}, {7, 7}, {5000, MaxSize}} {
		off, lim, err := Window(c.size, "")
		if err != nil || off != 0 || lim != c.want {
			t.Errorf("Window(%d) = %d, %d, %v; want 0, %d", c.size, off, lim, err, c.want)
		}
	}
}

func TestWindow_RefusesATokenItDidNotWrite(t *testing.T) {
	for _, tok := range []string{"%%%", "b2Zmc2V0OjQ", "bzow", "bzotMQ", "bzp4"} {
		if _, _, err := Window(10, tok); !errors.Is(err, ErrBadToken) {
			t.Errorf("Window(%q) err = %v, want ErrBadToken", tok, err)
		}
	}
}

// Two pages of one list give each item once, and the last page has no token.
func TestSlice_TwoPagesGiveEachItemOnce(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	seen := map[int]int{}
	token := ""
	pages := 0
	for {
		off, lim, err := Window(3, token)
		if err != nil {
			t.Fatalf("Window: %v", err)
		}
		page, next := Slice(items, off, lim)
		pages++
		for _, v := range page {
			seen[v]++
		}
		if next == "" {
			break
		}
		token = next
	}
	if pages != 2 {
		t.Fatalf("pages = %d, want 2", pages)
	}
	for _, v := range items {
		if seen[v] != 1 {
			t.Fatalf("item %d seen %d times", v, seen[v])
		}
	}
	if page, next := Slice(items, 9, 3); len(page) != 0 || next != "" {
		t.Fatalf("past the end = %v, %q", page, next)
	}
}

func TestNext_WithNoTotalAFullPageHasAToken(t *testing.T) {
	if Next(0, 2, 2, -1) == "" {
		t.Error("a full page with no total has no next token")
	}
	if Next(0, 2, 1, -1) != "" {
		t.Error("a short page has a next token")
	}
	if Next(2, 2, 2, 4) != "" {
		t.Error("the last full page of a known total has a next token")
	}
	off, _, err := Window(2, Next(0, 2, 2, -1))
	if err != nil || off != 2 {
		t.Errorf("round trip offset = %d, %v; want 2", off, err)
	}
}

func TestConversionsClampAndNeverWrap(t *testing.T) {
	if Int32(-1) != 0 || Int32(7) != 7 || Int32(math.MaxInt32+1) != math.MaxInt32 {
		t.Error("Int32 does not clamp")
	}
	if Uint32(-1) != 0 || Uint32(7) != 7 || Uint32(math.MaxUint32+1) != math.MaxUint32 {
		t.Error("Uint32 does not clamp")
	}
	if Int(7) != 7 || Int(math.MaxUint64) != math.MaxInt32 {
		t.Error("Int does not clamp")
	}
}
