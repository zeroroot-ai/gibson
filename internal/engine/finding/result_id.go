// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// resultIDNamespace is the UUID namespace of a finding id that comes from an
// idempotency key.
var resultIDNamespace = uuid.MustParse("6f1d3c2a-5b7e-4f10-9a8c-2d4e6b8f0a13")

// ResultID is the id of a finding that a submitter sends with an idempotency
// key (gibson#1448). The same key from the same submitter in the same tenant
// names the same finding, so a second read of one result of a tool updates
// it. The submitter is the authenticated identity of the caller, never a name
// that the caller sets, so one component cannot name the finding of another
// (review R6). Both submit paths use this one rule.
func ResultID(tenant, submitter, key string) types.ID {
	return types.ID(uuid.NewSHA1(resultIDNamespace, []byte(tenant+"\x00"+submitter+"\x00"+key)).String())
}
