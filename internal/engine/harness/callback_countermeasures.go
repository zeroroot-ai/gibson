// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	"buf.build/go/protovalidate"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// GetCountermeasures returns the defensive countermeasures that counter one
// ATT&CK technique, from the D3FEND pack of the embedded catalog (gibson#1487). A
// fix agent reads them when it plans a fix.
//
// The catalog is the same for every tenant, so the call reads no tenant. A
// technique that no countermeasure counters, and an empty technique, give an empty
// list and no error. A request that fails its validation rules, such as a value that is not an
// ATT&CK technique id, is refused in the answer (INVALID_ARGUMENT).
func (s *HarnessCallbackService) GetCountermeasures(
	_ context.Context, req *harnesspb.GetCountermeasuresRequest,
) (*harnesspb.GetCountermeasuresResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return &harnesspb.GetCountermeasuresResponse{ //nolint:nilerr // the refusal is the response, not a transport error
			Error: &harnesspb.HarnessError{
				Code: commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, Message: "the request is not valid: " + err.Error(),
			}}, nil
	}
	pack, ok := ontology.EmbeddedCatalog().Get(ontology.D3FENDPackName)
	if !ok {
		return &harnesspb.GetCountermeasuresResponse{Error: &harnesspb.HarnessError{
			Code: commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, Message: "the catalog holds no countermeasure pack",
		}}, nil
	}
	found := pack.CountermeasuresFor(req.GetTechnique())
	out := make([]*harnesspb.Countermeasure, 0, len(found))
	for _, c := range found {
		out = append(out, &harnesspb.Countermeasure{
			Id: c.ID, Name: c.Name, Tactic: c.Tactic, NistControls: append([]string(nil), c.NISTControls...),
		})
	}
	return &harnesspb.GetCountermeasuresResponse{Countermeasures: out}, nil
}
