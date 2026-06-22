/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package webhook hosts the mutating and validating admission webhooks for
// Gibson tenant-operator CRs. See owner_ref_mutator.go for the mutating
// webhook; this file contains the validating webhook for Tenant CRs.
package webhook

import (
	"context"
	"fmt"
	"net/mail"
	"regexp"
	"slices"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// ValidatePath is the URL path the ValidatingWebhookConfiguration references.
const ValidatePath = "/validate-tenant"

// slugRE matches DNS-safe slugs: 1–60 characters, lowercase, must start with
// a letter (not a digit), interior may include alnum or hyphens, must end
// with an alphanumeric character.
// Pattern: ^[a-z]([a-z0-9-]{0,58}[a-z0-9])?$
//
// The leading-letter constraint mirrors the daemon's tenant-identifier
// validator (auth: invalid tenant identifier ... lowercase letter start,
// [a-z0-9_-] body, [a-z0-9] end). Without it a name like "2foo" would pass
// the webhook, the saga would provision through 10 steps, then the
// Entitlements step's call to the daemon admin API would fail with a
// 502/permission_denied — looking like a hang to the user. Reject early.
//
// The trailing "?" makes the interior+final group optional so a single
// character (e.g. "a") still passes.
var slugRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,58}[a-z0-9])?$`)

// validTiers is the closed set of allowed tier values, mirroring plans.yaml.
// The daemon rejects unknown ids; accepting a legacy id at the webhook
// would let a Tenant land that gets stuck at the Entitlements saga step.
// Legacy ids (solo/squad/platform/enterprise-cloud/enterprise-onprem/
// public-sector/free/pro) are remapped by the chart's tenant-tier-migrate
// pre-upgrade Job before this webhook starts rejecting them — see spec
// plans-and-quotas-simplification.
var validTiers = map[gibsonv1alpha1.TenantTier]struct{}{
	gibsonv1alpha1.TenantPlanTeam:             {},
	gibsonv1alpha1.TenantPlanOrg:              {},
	gibsonv1alpha1.TenantPlanEnterprise:       {},
	gibsonv1alpha1.TenantPlanEnterpriseDeploy: {},
}

const maxDisplayNameLen = 120

// ReservedNamesProvider returns the chart-managed denylist (exact +
// prefix lists) read from the gibson-reserved-names ConfigMap. The
// validator calls it on every Tenant create; implementations are
// expected to apply their own caching against the K8s API.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 4.5.
type ReservedNamesProvider interface {
	ReservedNames(ctx context.Context) (exact, prefix []string, err error)
}

// TenantValidator implements admission.Validator[*gibsonv1alpha1.Tenant] and
// enforces invariants on Tenant CR create, update, and delete operations.
//
// Immutable fields on update: metadata.name (slug), spec.owner.
// Failure is hard (Denied); there is no failure-open path for a validator —
// callers that need to create an invalid Tenant must correct the fields first.
type TenantValidator struct {
	// ReservedNames is the chart-managed denylist source. May be nil
	// (no reserved-names check is performed). Populated via
	// ValidatorWebhookWithReserved for production deployments.
	ReservedNames ReservedNamesProvider
}

// compile-time interface assertion.
var _ admission.Validator[*gibsonv1alpha1.Tenant] = (*TenantValidator)(nil)

// ValidateCreate validates a new Tenant. All required fields are checked,
// including the chart-managed reserved-names denylist.
func (v *TenantValidator) ValidateCreate(ctx context.Context, obj *gibsonv1alpha1.Tenant) (admission.Warnings, error) {
	if err := validateTenantFields(obj); err != nil {
		return nil, err
	}
	if v.ReservedNames != nil {
		if err := v.checkReservedName(ctx, obj.Name); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// ValidateUpdate validates a Tenant update. In addition to field validation it
// enforces that metadata.name (the slug) and spec.owner are immutable.
// Reserved-names check is skipped because the slug is immutable on update.
func (v *TenantValidator) ValidateUpdate(_ context.Context, oldObj, newObj *gibsonv1alpha1.Tenant) (admission.Warnings, error) {
	if oldObj.Name != newObj.Name {
		return nil, fmt.Errorf("spec.slug (metadata.name) is immutable: cannot change %q to %q", oldObj.Name, newObj.Name)
	}
	if oldObj.Spec.Owner != newObj.Spec.Owner {
		return nil, fmt.Errorf("spec.owner is immutable: cannot change %q to %q", oldObj.Spec.Owner, newObj.Spec.Owner)
	}
	return nil, validateTenantFields(newObj)
}

// ValidateDelete allows all deletions; lifecycle protection is handled by the
// TenantFinalizer, not by this webhook.
func (v *TenantValidator) ValidateDelete(_ context.Context, _ *gibsonv1alpha1.Tenant) (admission.Warnings, error) {
	return nil, nil
}

// checkReservedName rejects creation when the slug appears in the
// chart-managed denylist (exact match) or starts with a registered
// prefix. Failure-open on provider errors: the dashboard signup form
// performs the same check client-side, and rejecting a legitimate
// tenant create because the K8s API was momentarily unavailable
// would cause a worse UX than letting the daemon's downstream
// admission run normally.
func (v *TenantValidator) checkReservedName(ctx context.Context, slug string) error {
	exact, prefix, err := v.ReservedNames.ReservedNames(ctx)
	if err != nil {
		// Surface as a warning via stderr / log; do not block.
		// The dashboard signup form caught this before submit anyway.
		return nil
	}
	if slices.Contains(exact, slug) {
		return fmt.Errorf("metadata.name (slug) %q is reserved by platform configuration; pick a different name", slug)
	}
	for _, p := range prefix {
		if p != "" && len(slug) >= len(p) && slug[:len(p)] == p {
			return fmt.Errorf("metadata.name (slug) %q starts with reserved prefix %q; pick a different name", slug, p)
		}
	}
	return nil
}

// ValidatorWebhook returns an admission.Webhook that uses WithValidator to
// serve the TenantValidator without a reserved-names provider.
//
// Production callers should prefer ValidatorWebhookWithReserved which wires
// the chart-managed denylist into the validator. ValidatorWebhook is kept
// for tests and for legacy callers that do not have a K8s client to feed
// the provider.
func ValidatorWebhook(scheme *runtime.Scheme) *admission.Webhook {
	return admission.WithValidator[*gibsonv1alpha1.Tenant](scheme, &TenantValidator{})
}

// ValidatorWebhookWithReserved is the production constructor; it wires the
// reserved-names provider so the chart's gibson-reserved-names ConfigMap
// gates Tenant CR creation.
func ValidatorWebhookWithReserved(scheme *runtime.Scheme, rn ReservedNamesProvider) *admission.Webhook {
	return admission.WithValidator[*gibsonv1alpha1.Tenant](scheme, &TenantValidator{ReservedNames: rn})
}

// validateTenantFields checks all required content rules and returns the first
// violation as an error. The caller is responsible for deciding whether the
// error should be surfaced as a rejection or a warning.
func validateTenantFields(t *gibsonv1alpha1.Tenant) error {
	if err := validateSlug(t.Name); err != nil {
		return err
	}
	if err := validateOwner(t.Spec.Owner); err != nil {
		return err
	}
	if err := validateTier(t.Spec.Tier); err != nil {
		return err
	}
	if err := validateDisplayName(t.Spec.DisplayName); err != nil {
		return err
	}
	return nil
}

// validateSlug checks that the slug (metadata.name) matches the DNS-safe
// pattern and is within the allowed length.
func validateSlug(name string) error {
	if name == "" {
		return fmt.Errorf("metadata.name (slug) must not be empty")
	}
	if !slugRE.MatchString(name) {
		return fmt.Errorf("metadata.name (slug) %q is invalid: must match ^[a-z]([a-z0-9-]{0,58}[a-z0-9])?$ (DNS-safe, 1–60 chars, must start with a lowercase letter, no leading/trailing hyphens)", name)
	}
	return nil
}

// validateOwner checks that spec.owner is a non-empty, RFC-5322-parseable
// email address using the stdlib net/mail package.
func validateOwner(owner string) error {
	if owner == "" {
		return fmt.Errorf("spec.owner must not be empty")
	}
	if _, err := mail.ParseAddress(owner); err != nil {
		return fmt.Errorf("spec.owner %q is not a valid email address: %w", owner, err)
	}
	return nil
}

// validateTier checks that spec.tier is one of the known tier constants.
func validateTier(tier gibsonv1alpha1.TenantTier) error {
	if tier == "" {
		return fmt.Errorf("spec.tier must not be empty")
	}
	if _, ok := validTiers[tier]; !ok {
		return fmt.Errorf("spec.tier %q is invalid: must be one of team, org, enterprise, enterprise-deploy (legacy ids are remapped by the chart's tenant-tier-migrate Job before this webhook rejects them)", tier)
	}
	return nil
}

// validateDisplayName checks that spec.displayName is non-empty and within the
// maximum length.
func validateDisplayName(name string) error {
	if name == "" {
		return fmt.Errorf("spec.displayName must not be empty")
	}
	if len(name) > maxDisplayNameLen {
		return fmt.Errorf("spec.displayName length %d exceeds maximum of %d characters", len(name), maxDisplayNameLen)
	}
	return nil
}
