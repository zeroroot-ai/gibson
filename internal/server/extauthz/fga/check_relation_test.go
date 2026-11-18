// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"testing"
)

func TestCheckRelation_AsksTheExactQuestion(t *testing.T) {
	mock := &objectCapturingFGA{allowed: true}
	c := NewCachedChecker(NewChecker(mock, &Registry{}), 0, 0)

	ok, err := c.CheckRelation(context.Background(), "tenant:acme#member", "can_use", "model:acme/m1",
		map[string]any{"k": "v"})
	if err != nil || !ok {
		t.Fatalf("CheckRelation = %v, %v, want true and no error", ok, err)
	}
	got := mock.captured()
	if len(got) != 1 {
		t.Fatalf("FGA asked %d questions, want 1", len(got))
	}
	if got[0].User != "tenant:acme#member" || got[0].Relation != "can_use" || got[0].Object != "model:acme/m1" {
		t.Errorf("question = %+v", got[0])
	}
	if got[0].Context == nil || (*got[0].Context)["k"] != "v" {
		t.Errorf("condition context = %v, want k=v", got[0].Context)
	}
}

func TestCheckRelation_DoesNotCache(t *testing.T) {
	mock := &objectCapturingFGA{allowed: true}
	c := NewCachedChecker(NewChecker(mock, &Registry{}), 0, 0)
	for range 2 {
		if _, err := c.CheckRelation(context.Background(), "u", "r", "o:1", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(mock.captured()); n != 2 {
		t.Errorf("FGA asked %d times for 2 calls, want 2: a revoked grant must stop the next call", n)
	}
}

func TestCheckRelation_RefusesAnEmptyField(t *testing.T) {
	mock := &objectCapturingFGA{allowed: true}
	c := NewChecker(mock, &Registry{})
	for _, args := range [][3]string{{"", "r", "o"}, {"u", "", "o"}, {"u", "r", ""}} {
		if ok, err := c.CheckRelation(context.Background(), args[0], args[1], args[2], nil); ok || err == nil {
			t.Errorf("CheckRelation(%v) = %v, %v, want false and an error", args, ok, err)
		}
	}
	if len(mock.captured()) != 0 {
		t.Error("FGA was asked with an empty field")
	}
}
