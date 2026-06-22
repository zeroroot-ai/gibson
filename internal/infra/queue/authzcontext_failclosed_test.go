package queue

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Regression for gibson#546: the work-envelope AuthzContext the daemon dispatches
// must NOT carry any fail-open / permissive flag. Component-side authorization is
// fail-closed by default; the daemon never transmits a value that could flip a
// worker into fail-open. This test locks that invariant so a future field
// addition that defaults to "allow on unavailable" can't silently regress it.
func TestAuthzContext_NoFailOpenField(t *testing.T) {
	// 1. Marshalled wire form carries no fail-open-ish key.
	ac := AuthzContext{RunID: "run-1", IssuedAt: 1, TTLSeconds: 600}
	b, err := json.Marshal(ac)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(b, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for k := range asMap {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "fail") || strings.Contains(lk, "open") ||
			strings.Contains(lk, "allow") || strings.Contains(lk, "bypass") ||
			strings.Contains(lk, "insecure") {
			t.Fatalf("AuthzContext must not carry a fail-open/permissive field; found %q", k)
		}
	}

	// 2. The struct's field set is exactly the fail-closed trio. A new field
	//    forces a deliberate review of this guard.
	want := map[string]bool{"RunID": true, "IssuedAt": true, "TTLSeconds": true}
	tp := reflect.TypeOf(AuthzContext{})
	if tp.NumField() != len(want) {
		t.Fatalf("AuthzContext field count changed (%d); review fail-open invariant before adding fields", tp.NumField())
	}
	for i := 0; i < tp.NumField(); i++ {
		if !want[tp.Field(i).Name] {
			t.Fatalf("unexpected AuthzContext field %q — review the fail-open invariant", tp.Field(i).Name)
		}
	}
}
