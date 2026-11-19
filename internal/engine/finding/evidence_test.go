// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"testing"

	"github.com/stretchr/testify/assert"

	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// TestEvidenceTypeName_CoversTheWholeEnum proves that each type in the enum has
// its own name and that the two functions invert each other. A new enum value
// with no case fails this test.
func TestEvidenceTypeName_CoversTheWholeEnum(t *testing.T) {
	seen := map[sdkfinding.EvidenceType]typespb.EvidenceType{}
	for value, name := range typespb.EvidenceType_name {
		et := typespb.EvidenceType(value)
		if et == typespb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED {
			assert.Equal(t, sdkfinding.EvidenceOther, EvidenceTypeName(et))
			continue
		}
		got := EvidenceTypeName(et)
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s share the name %q", name, prev, got)
		}
		seen[got] = et
		assert.NotEqual(t, typespb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED, EvidenceTypeFromName(got), name)
		assert.Equal(t, et, EvidenceTypeFromName(got), name)
	}
	assert.Equal(t, typespb.EvidenceType_EVIDENCE_TYPE_OTHER, EvidenceTypeFromName("no such type"))
}
