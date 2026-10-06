// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"reflect"
	"testing"
)

func TestGrantTupleRelation(t *testing.T) {
	want := map[string]string{
		"can_read":      "direct_read",
		"can_configure": "direct_configure",
		"can_execute":   "direct_execute",
		"can_invoke":    "can_invoke",
	}
	for action, relation := range want {
		got, ok := GrantTupleRelation(action)
		if !ok || got != relation {
			t.Errorf("GrantTupleRelation(%q) = %q, %v, want %q, true", action, got, ok, relation)
		}
	}
	for _, action := range []string{"", "direct_read", "owner", "can_use"} {
		if got, ok := GrantTupleRelation(action); ok {
			t.Errorf("GrantTupleRelation(%q) = %q, true, want false", action, got)
		}
	}
}

func TestGrantActions(t *testing.T) {
	want := []string{"can_configure", "can_execute", "can_invoke", "can_read"}
	if got := GrantActions(); !reflect.DeepEqual(got, want) {
		t.Errorf("GrantActions() = %v, want %v", got, want)
	}
}
