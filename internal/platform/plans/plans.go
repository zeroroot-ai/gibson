// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package plans is gibson's canonical plan registry: the closed set of plan
// ids a tenant may hold, plus the two policy bits the platform needs about
// each one — whether it can be acquired through self-serve signup, and
// whether it is a paid plan that requires an active subscription.
//
// # Where the plan data actually lives
//
// The upstream source of truth is plans.yaml, owned by the deploy chart
// (helm/gibson-workloads/files/plans.yaml, mirrored into gibson-operators).
// gibson does not ship a copy of that file: it is chart data, and adding a
// third copy here would add a third thing to drift.
//
// gibson already carried one in-repo mirror of the plan ids — the TenantTier
// constants in operators/tenant/api/v1alpha1, from which the Tenant CRD's
// tier enum is generated. That mirror is unreachable from the daemon (it
// pulls the Kubernetes API machinery in) and it records only the ids, not
// whether a plan is self-serve or paid. This package is the reachable-from-
// everywhere mirror; plans_drift_test.go fails if its id set drifts from the
// kubebuilder enum marker on TenantSpec.Tier, and the tenant admission
// webhook now validates through this package instead of keeping its own
// hand-maintained set. Net mirror count is unchanged.
//
// # Why the daemon needs the self-serve / paid bits
//
// SignupService.Signup used to forward whatever tier string the caller sent
// straight into the pending-provisioning queue, validated only against the
// empty string. A caller could name any plan — including the contact-sales
// on-prem plan, which is never sold self-serve — and the operator would
// provision a tenant at that tier, sizing the per-tenant data plane
// accordingly. Signup now resolves the requested tier through this package
// and refuses anything that is not a self-serve plan.
package plans

import "strings"

// Plan is one canonical plan and the policy bits the platform enforces on it.
// It deliberately carries no quota numbers, price, or Stripe product id: those
// live in plans.yaml and reach the runtime through the entitlements seam
// (pkg/billing/entitlements), never through gibson source.
type Plan struct {
	// ID is the canonical plan id — the exact string that appears in
	// plans.yaml, in the Tenant CR's spec.tier, and in the
	// pending_tenant_provisioning.tier column.
	ID string

	// SelfServe reports whether the plan can be acquired through the
	// self-serve signup flow. A plan priced "contact sales" has no Stripe
	// product and no trial, so there is no path by which a self-serve signup
	// could legitimately land on it.
	SelfServe bool

	// Paid reports whether holding the plan requires an active Stripe
	// subscription or trial. Contact-sales plans are unbilled through Stripe
	// (they are invoiced out of band), so they are not Paid in this sense.
	Paid bool
}

// canonical is the closed plan set, ordered as plans.yaml orders it.
//
// Keep in sync with plans.yaml. TestPlanIDsMatchCRDEnum enforces that the id
// set here equals the kubebuilder enum on TenantSpec.Tier, which is itself
// generated from plans.yaml — so a plan added upstream without being added
// here fails CI at the operator boundary.
var canonical = []Plan{
	{ID: "team", SelfServe: true, Paid: true},
	{ID: "org", SelfServe: true, Paid: true},
	{ID: "enterprise", SelfServe: true, Paid: true},
	// enterprise-deploy is the on-prem / federal plan: pricing.contactSales,
	// no stripeProductId, no trialDays. It is provisioned by an administrator
	// through AdminProvisionTenant, never by a self-serve signup.
	{ID: "enterprise-deploy", SelfServe: false, Paid: false},
}

// byID indexes canonical for O(1) exact-match lookup. Built at init so
// Lookup never allocates.
var byID = func() map[string]Plan {
	m := make(map[string]Plan, len(canonical))
	for _, p := range canonical {
		m[p.ID] = p
	}
	return m
}()

// Lookup resolves a plan id to its Plan. The match is exact: no case folding,
// no whitespace tolerance beyond trimming, no legacy-id remapping. Legacy ids
// (solo/squad/platform/enterprise-cloud/…) were rewritten by the chart's
// tenant-tier-migrate pre-upgrade Job and must not be silently accepted here —
// accepting one would let a tenant land on a tier the rest of the platform
// cannot price.
//
// ok is false for the empty string, for whitespace, and for any id outside
// the canonical set. Callers MUST treat !ok as a hard reject, never as
// "assume the default plan".
func Lookup(id string) (Plan, bool) {
	p, ok := byID[strings.TrimSpace(id)]
	return p, ok
}

// Known reports whether id names a canonical plan. Convenience wrapper over
// Lookup for callers that only need the membership test.
func Known(id string) bool {
	_, ok := Lookup(id)
	return ok
}

// IDs returns the canonical plan ids in plans.yaml order. The returned slice
// is a fresh copy; mutating it does not affect the registry.
func IDs() []string {
	out := make([]string, 0, len(canonical))
	for _, p := range canonical {
		out = append(out, p.ID)
	}
	return out
}

// SelfServeIDs returns the ids of the plans a self-serve signup may request,
// in plans.yaml order. Used to build the operator-facing error message when a
// signup names a plan it cannot buy.
func SelfServeIDs() []string {
	out := make([]string, 0, len(canonical))
	for _, p := range canonical {
		if p.SelfServe {
			out = append(out, p.ID)
		}
	}
	return out
}
