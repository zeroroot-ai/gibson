// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cueruntime

import (
	"strings"
	"testing"
)

// And the rewrite must leave alone a colon import of a package whose
// declaration was NOT renamed. Those still resolve, and rewriting them would
// change files for no reason.
func TestRewriteColonImports_TouchesOnlyRewrittenPackages(t *testing.T) {
	in := []byte(`import (
	"github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1:jobpb"
	"github.com/zeroroot-ai/sdk/api/proto/gibson/types/v1:typespb"
	"time"
)`)

	got := string(rewriteColonImports(in))

	if !strings.Contains(got, `jobpb "github.com/zeroroot-ai/sdk/api/proto/gibson/job/v1"`) {
		t.Errorf("job/v1 was not rewritten to the alias form:\n%s", got)
	}
	if !strings.Contains(got, `"github.com/zeroroot-ai/sdk/api/proto/gibson/types/v1:typespb"`) {
		t.Errorf("types/v1 was rewritten although its package was not renamed:\n%s", got)
	}
	if !strings.Contains(got, `"time"`) {
		t.Errorf("an unrelated import was altered:\n%s", got)
	}
}
