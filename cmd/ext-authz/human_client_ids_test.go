// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"reflect"
	"testing"
)

func TestLoadHumanClientIDs(t *testing.T) {
	t.Setenv("EXT_AUTHZ_HUMAN_CLIENT_IDS", " 334268812578094081@gibson , ,cli@gibson,")
	if got, want := loadHumanClientIDs(), []string{"334268812578094081@gibson", "cli@gibson"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loadHumanClientIDs() = %v, want %v", got, want)
	}
	t.Setenv("EXT_AUTHZ_HUMAN_CLIENT_IDS", "")
	if got := loadHumanClientIDs(); len(got) != 0 {
		t.Fatalf("unset must mean no human clients, got %v", got)
	}
}
