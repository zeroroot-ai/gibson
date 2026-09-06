// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUnsealEscrowSpecOmitsEmptySourceSecret is the failing fixture for the
// deploy#1737 pointer fix. As a value type, omitempty never omits a struct,
// so an UnsealEscrowSpec with no source Secret marshaled
// sourceSecret:{name:"",key:""}. The CRD's minLength validation then
// rejected EVERY operator write of a PlatformBootstrap rendered without a
// sourceSecret, which since the static seal (deploy#1750) is every profile:
// the operator could not even add its finalizer, and nothing bootstrapped.
func TestUnsealEscrowSpecOmitsEmptySourceSecret(t *testing.T) {
	spec := UnsealEscrowSpec{Destination: UnsealEscrowManagedExternally}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "sourceSecret") {
		t.Fatalf("an UnsealEscrowSpec with no source Secret must omit sourceSecret entirely, got %s", raw)
	}
}
