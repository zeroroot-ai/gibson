// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WorldView is the agent's only read of the tenant World (ADR-0012): the
// emit-only Observe write contract's read complement. It returns a
// server-projected, mission-Scope-limited slice of the World — never the raw
// brain. Every entity is named by an opaque, server-minted handle the agent
// cannot construct or iterate, so enumerating past the slice boundary is
// unrepresentable.
//
// The slice's tenant and scope are resolved server-side off the daemon's own
// mission record (observationAttribution), exactly as Observe resolves them —
// the request carries no tenant field (harness_callback.proto) and cannot widen
// the slice. focus narrows to already-issued handles at full detail; a handle
// never issued to this caller is refused, so focus can only zoom in.
//
// When no source is wired (SetWorldViewSource never called) the read FAILS. It
// used to mirror Observe's no-op-when-unsinked behaviour and return an empty
// slice, and that was wrong: emitting into a void loses one observation, but
// answering a read with an empty World tells the agent the tenant knows nothing.
// An agent cannot tell that apart from a genuinely empty World, so it proceeds
// on a false negative — in a security product, "no prior findings for this
// target" when the truth is "I could not look".
//
// The SDK already refuses to do this on the client half of the same RPC:
// "Failing is the only honest answer — an empty slice would read as 'the World
// is empty'" (serve/worldview.go). Both halves now agree.
//
// A nil source is a misconfigured daemon, not a supported mode, so this surfaces
// a real problem instead of hiding it.
func (s *HarnessCallbackService) WorldView(ctx context.Context, req *harnesspb.WorldViewRequest) (*harnesspb.WorldViewResponse, error) {
	if s.worldViewSource == nil {
		return nil, status.Error(codes.Unavailable,
			"WorldView is not available: no world-view source is wired on this daemon")
	}

	// Resolve the mission record for tenant + scope. getHarness has already
	// refused an empty mission tenant and any caller whose tenant differs from
	// it; observationAttribution refuses a scope-less mission. The agent authors
	// neither — both come from the daemon's mission record (ADR-0012).
	harness, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	attr, err := observationAttribution(harness)
	if err != nil {
		return nil, err
	}

	result, err := s.worldViewSource(ctx, WorldViewQuery{
		Tenant:    attr.Tenant,
		ScopeID:   attr.ScopeID,
		MissionID: attr.MissionID,
		Focus:     req.GetFocus(),
	})
	if err != nil {
		// A refused focus handle is the caller's error (it named a handle never
		// issued to this slice), surfaced as an in-band HarnessError so the SDK
		// client sees the emit-contract error shape rather than a transport one.
		if status.Code(err) == codes.PermissionDenied {
			return &harnesspb.WorldViewResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
					Message: err.Error(),
				},
			}, nil
		}
		return &harnesspb.WorldViewResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	entities := make([]*harnesspb.WorldEntity, 0, len(result.Entities))
	for _, e := range result.Entities {
		entities = append(entities, &harnesspb.WorldEntity{
			Handle:     e.Handle,
			Kind:       e.Kind,
			Label:      e.Label,
			Attributes: e.Attributes,
		})
	}
	return &harnesspb.WorldViewResponse{
		Entities:  entities,
		Truncated: result.Truncated,
	}, nil
}

// WorldViewQuery is the resolved, server-authored request for a World slice.
// Tenant, ScopeID and MissionID are read off the daemon's mission record, never
// from the agent; Focus is the agent's list of already-issued handles to zoom
// into.
type WorldViewQuery struct {
	Tenant    string
	ScopeID   string
	MissionID string
	Focus     []string
}

// WorldEntityRecord is one projected entity in a World slice. Handle is the
// opaque, server-minted reference (the only name the agent has); Kind/Label are
// human- and LLM-readable; Attributes is the level-of-detail projection
// (summarized for the unfocused slice, complete for a focused one).
type WorldEntityRecord struct {
	Handle     string
	Kind       harnesspb.WorldEntityKind
	Label      string
	Attributes map[string]string
}

// WorldViewResult is a projected World slice. Truncated is true when the slice
// exceeded the server-side projection cap and entities were dropped.
type WorldViewResult struct {
	Entities  []WorldEntityRecord
	Truncated bool
}

// WorldViewSource projects a mission-Scope-limited slice of the tenant World.
// The daemon wires it to the per-tenant brain via CallbackManager.SetWorldViewSource;
// it mints the handles, applies the level-of-detail summary, enforces the
// projection cap, and resolves focus (refusing, with codes.PermissionDenied, any
// focus handle it did not issue to this slice). When unset, WorldView is disabled.
type WorldViewSource func(ctx context.Context, q WorldViewQuery) (WorldViewResult, error)
