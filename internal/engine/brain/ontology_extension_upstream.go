// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain — ontology_extension_upstream.go: the tenant-owner "submit
// upstream" action (ADR-0133's final arrow, gibson#393, epic
// #376).
//
// ADR-0133's full lifecycle is "Agent captures -> proposal -> explicit
// tenant-owner approval -> tenant extension (live, per-tenant,
// mission-pinned) -> owner 'submit upstream' -> contribution (a PR into the
// SDK, which anyone may open) -> platform-owner review + merge + rollout ->
// catalog pack -> tenant enable toggle". ontology_extension.go
// (gibson#391/#392) builds every arrow up to and including "tenant
// extension". This file builds the next one: rendering that live tenant
// extension into the exact Domain Pack source artifact a contribution PR
// would carry.
//
// Opening the PR itself is deliberately NOT built here. gibson holds no
// GitHub credential or bot identity scoped to the `sdk` repository, and the
// ADR text itself says a contribution is "a PR into the SDK, which anyone
// may open" — naming a human action, not an automated one, the same way
// this org treats other owner-only steps (DNS, Stripe keys, required
// reviewers) as hand-offs rather than something a service account does.
// Inventing a credential or a bot identity here to close that gap would be
// exactly the kind of hack ADR-0027 rules out. SubmitOntologyExtensionUpstream
// therefore stops at rendering: it returns the artifact and the daemon's
// gRPC handler (ontology_extension_service.go) hands it back to the tenant
// owner to commit and submit themselves.
package brain

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// upstreamContributionPackVersion is the Version every rendered contribution
// fragment carries. A submit-upstream render is always a brand-new candidate
// pack — distinct from, and never derived from, the tenant's own
// taxonomy.Registry version (OntologyProposalState.PromotedVersion) — so it
// always starts at 1, mirroring how a freshly authored catalog pack (e.g.
// ontology/packs/main.json) starts its own versioning at 1.
const upstreamContributionPackVersion = 1

// OntologyProposalNotPromotedError is returned by SubmitOntologyExtensionUpstream
// when (kind, label) names a proposal this tenant's World has observed, but
// which is not yet promoted into a live tenant extension (ADR-0133:
// "Submit-upstream is available only from a live tenant extension — a
// tenant vouches for it by using it first"). Approved-but-not-yet-settled and
// still-pending proposals both refuse this way; Status distinguishes them for
// the caller's error message.
type OntologyProposalNotPromotedError struct {
	Kind   taxonomy.ProposalKind
	Label  string
	Status OntologyProposalStatus
}

func (e *OntologyProposalNotPromotedError) Error() string {
	return fmt.Sprintf(
		"brain: ontology extension proposal for %s %q is not yet a live tenant extension (status: %s); "+
			"submit-upstream is available only from a live tenant extension",
		e.Kind, e.Label, e.Status,
	)
}

// SubmitOntologyExtensionUpstream is the entry point the tenant-owner-gated
// OntologyExtensionService.SubmitOntologyExtensionUpstream RPC calls
// (gibson#393, ADR-0133): render a LIVE tenant extension — a
// proposal that has already been promoted (state.Promoted, ADR-0133)
// — as an ontology.DomainPack contribution fragment: pure data (ADR-0133),
// never code, in the exact JSON shape ExportDomainPack/Import
// already establish as this platform's one Domain Pack source format
// (gibson#378).
//
// Refuses with *OntologyProposalNotFoundError when no matching proposal has
// ever been observed, and with *OntologyProposalNotPromotedError when one
// has but is not yet live. Unlike ProposeOntologyExtension/
// ApproveOntologyExtension, this is a pure read: it submits no event and
// mutates nothing, because "submit upstream" nominates existing, already-live
// structure for external review — it never itself changes this tenant's
// World.
//
// The returned pack's Author identifies the submitting tenant (ADR-0133:
// "the tenant that proposed a tenant extension"); Visibility is
// deliberately left unclassified (the zero value) rather than "private" or
// "public" — a contribution candidate is neither yet: DomainPack.Validate
// documents the zero value as exactly this "not yet classified" case, and
// classification as public is the platform owner's decision at PR-review time
// (ADR-0133), not this tenant's.
func (e *Engine) SubmitOntologyExtensionUpstream(_ context.Context, kind taxonomy.ProposalKind, label string) (*ontology.DomainPack, error) {
	if err := taxonomy.ValidIdentifier(label); err != nil {
		return nil, &taxonomy.InvalidProposalError{Kind: kind, Label: label, Err: err}
	}
	state, ok := e.ontologyProposalState(kind, label)
	if !ok {
		return nil, &OntologyProposalNotFoundError{Kind: kind, Label: label}
	}
	if !state.Promoted {
		return nil, &OntologyProposalNotPromotedError{Kind: kind, Label: label, Status: state.Status}
	}

	pack := &ontology.DomainPack{
		Name:    label,
		Version: upstreamContributionPackVersion,
		Author:  e.World.Tenant,
	}
	switch kind {
	case taxonomy.ProposedNodeLabel:
		pack.TaxonomyNodeLabels = []string{label}
		// Carry the label's written key form so the receiving install keys it
		// exactly as this one did (gibson#484). Resolve it from the authoritative
		// promotion registry (the label is promoted, so it is recorded there);
		// fall back to the deterministic default if absent. A runtime-promoted
		// node label is identified by DiscoveredNodeIdentityProperty, so an
		// imported contribution never splits into a duplicate node (gibson#1669).
		identity, ok := taxonomy.IdentityProperty(label)
		if !ok {
			identity = taxonomy.DiscoveredNodeIdentityProperty
		}
		pack.TaxonomyNodeIdentity = map[string]string{label: identity}
	case taxonomy.ProposedRelationshipType:
		pack.TaxonomyRelationshipTypes = []string{label}
	default:
		// Unreachable via the only exported path to a Promoted proposal
		// (ProposeOntologyExtension/ApproveOntologyExtension both fold
		// against taxonomy's own closed two-value ProposalKind vocabulary) —
		// fails closed rather than emit an empty, meaningless pack.
		return nil, fmt.Errorf("brain: submit ontology extension upstream: unrecognized proposal kind %v for label %q", kind, label)
	}

	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("brain: submit ontology extension upstream for %s %q: render an invalid pack fragment: %w", kind, label, err)
	}
	return pack, nil
}
