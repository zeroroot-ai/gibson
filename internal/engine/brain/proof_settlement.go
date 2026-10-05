// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// proof_settlement.go is the tenant-routing seam the SubmitProof RPC handler
// (internal/engine/harness, gibson#389) is built against (ADR-0131).
// It mirrors belief_substrate.go's pattern exactly: PlaceBet is written
// against brain.BeliefSubstrate rather than *Registry/*Engine directly so a
// daemon-side tenant-routing adapter can sit between "one shared value on
// HarnessCallbackService" and "one World per tenant" (ADR-0101); SubmitProof
// needs the same seam for its two Engine operations (resolving an enabled
// Domain Pack's CEL predicate binding, and settling a bet true).
//
// Tenant resolution is NOT a parameter here, again mirroring BeliefSubstrate:
// an implementation resolves it from ctx (in practice, auth.TenantFromContext,
// the same mechanism internal/server/daemon's tenantRoutedBeliefSubstrate
// already uses), never from caller-supplied data. SubmitProof passes the same
// ctx getHarness already validated against the caller's mission tenant, so
// this can never reach a tenant the caller does not own.

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

// ProofSettlementEngine is the tenant-scoped capability SubmitProof needs
// (gibson#389): resolve which enabled Domain Pack binds a CEL predicate name,
// and settle a bet true once that predicate fires against submitted evidence
// (Engine.SettleBetTrue). A concrete implementation is deliberately NOT
// published here, for the same reason belief_substrate.go's is not: nothing
// in this repo calls it yet until gibson#389's daemon-side adapter (mirroring
// internal/server/daemon/belief_substrate_adapter.go) wires it to a real
// *Registry.
type ProofSettlementEngine interface {
	// DomainPackPredicate resolves predicateName against ctx's tenant's
	// currently-enabled Domain Packs (ADR-0133), returning the bound CEL
	// expression text and whether one was found at all. Predicates are keyed
	// by a technique-shaped identifier (ADR-0131,
	// ontology.DomainPack.Predicates) — predicateName is that identifier
	// from the agent's perspective, resolved the same way
	// World.DomainPackPredicate already does for direct in-process readers.
	// ok is false, never an error, for a predicate name no enabled pack
	// binds: an unknown predicate is SubmitProof's fail-closed case
	// (ADR-0131), not a system failure. destructive is the pack's own
	// statement about the predicate (ADR-0132): true unless the pack names
	// the predicate as non-destructive.
	DomainPackPredicate(ctx context.Context, predicateName string) (expr string, destructive, ok bool, err error)

	// SettleBetTrue resolves ctx's tenant's Engine and delegates to its own
	// Engine.SettleBetTrue (bet_settlement.go): evaluate registry's predicate
	// against req's evidence and, if it fires, fold BetSettledTrue. See
	// Engine.SettleBetTrue's doc for the full (bool, error) contract.
	SettleBetTrue(ctx context.Context, registry *settlement.Registry, authorize DestructiveProofAuthorizer, req BetSettlementRequest) (bool, error)

	// RequestDestructiveAuthorization resolves ctx's tenant's Engine and
	// enqueues req against that tenant's own DestructiveAuthorizationQueue
	// (ADR-0132, gibson#390), returning immediately with the
	// pending request's id: the RequestDestructiveAuthorization RPC
	// handler's (internal/engine/harness) only dependency besides the two
	// methods above. The fleet keeps working while the human decision is
	// pending; this never blocks.
	RequestDestructiveAuthorization(ctx context.Context, req DestructiveAuthorizationRequest) (authorizationRequestID string, err error)
}
