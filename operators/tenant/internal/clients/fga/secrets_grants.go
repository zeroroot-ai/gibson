/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package fga is the operator's client to OpenFGA for writing and deleting
// tuples that project from AgentEnrollment CRDs.
// This file provides secret-specific grant helpers per spec secrets-broker
// Phase 8 (Tasks 21–22).
package fga

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// SecretCanResolveTuple returns the FGA tuple that grants a plugin_principal
// identity can_resolve access to all secrets scoped to the given tenant.
//
// Tuple shape:
//
//	(plugin_principal:<enrollmentUID>, can_resolve, secret:tenant-<tenantID>:*)
//
// OpenFGA does not support object wildcards in the tuple store directly (the
// "*" is not a native FGA wildcard). Instead we use the per-tenant secret
// object ID convention `secret:tenant-<tenantID>:*` which the daemon writes
// as a literal object ID representing the tenant-wide grant. The ext-authz
// sidecar and the daemon's authz interceptor both query `can_resolve` against
// this object ID for every GetCredential request, so writing this single tuple
// at plugin provisioning time grants the plugin access to all current and
// future secrets in the tenant without per-secret tuples.
//
// agent_principal and tool_principal callers are never passed to this function;
// they receive no can_resolve tuples to any secret:* object.
func SecretCanResolveTuple(enrollmentUID, tenantID string) Tuple {
	return Tuple{
		User:     fmt.Sprintf("plugin_principal:%s", enrollmentUID),
		Relation: "can_resolve",
		Object:   fmt.Sprintf("secret:tenant-%s/*", tenantID),
	}
}

// WriteSecretResolveGrant writes the can_resolve FGA tuple for a
// plugin_principal enrollment. Idempotent: if the tuple already exists,
// the function returns nil (ErrAlreadyExists is treated as success).
//
// This must only be called for plugin_principal enrollments. Callers are
// responsible for gating on PrincipalKind==plugin before invoking.
func WriteSecretResolveGrant(ctx context.Context, fgaClient Client, enrollmentUID, tenantID string) error {
	tuple := SecretCanResolveTuple(enrollmentUID, tenantID)
	if err := fgaClient.Write(ctx, []Tuple{tuple}); err != nil {
		if errors.Is(err, clients.ErrAlreadyExists) {
			// Tuple already exists — idempotent success.
			return nil
		}
		return fmt.Errorf("fga: WriteSecretResolveGrant enrollment=%s tenant=%s: %w",
			enrollmentUID, tenantID, err)
	}
	return nil
}

// TODO(non-plugin-isolation): future backfill code must inherit the
// can_resolve agent/tool denial constraint. Per spec
// non-plugin-secret-isolation Requirement 3.4, any retroactive or
// migration code that writes secret-related FGA tuples MUST refuse to
// write a `can_resolve` relation for any user other than a
// `plugin_principal:*`. The existing BackfillSecretResolveGrants below
// enforces this structurally by accepting only []PluginEnrollment as
// input — there is no agent or tool enrollment shape that this function
// will accept. Any future loosening of the input type (e.g., a generic
// EnrollmentDescriptor that also includes agents/tools), or a new
// migration tool that walks AgentEnrollment objects directly, MUST gate
// on PrincipalKind == plugin before calling fgaClient.Write with a
// can_resolve tuple, or it will silently re-introduce the structural
// regression that secrets-broker Spec 1 R8 explicitly forbids. The
// regression test
// `TestProvisioning_BackfillSecretGrantsRemainsPluginOnly`
// (internal/saga/flows/tuple_writer_test.go) pins this property for the
// current backfill helper; new helpers must add equivalent tests.

// PluginEnrollment is a minimal descriptor of an existing plugin_principal
// enrollment, used by BackfillSecretResolveGrants.
type PluginEnrollment struct {
	// EnrollmentUID is the stable identifier used in the FGA tuple subject
	// (plugin_principal:<EnrollmentUID>). Typically the Kubernetes object UID.
	EnrollmentUID string
	// TenantID is the tenant this plugin belongs to.
	TenantID string
}

// BackfillResult captures the outcome of a single backfill attempt for one
// plugin enrollment.
type BackfillResult struct {
	EnrollmentUID string
	TenantID      string
	// Written is true when a new tuple was written (false means it already existed).
	Written bool
	// Err is non-nil if the write failed.
	Err error
}

// BackfillSecretResolveGrants iterates over all provided plugin enrollments and
// writes the can_resolve tuple for any that do not already have one. It is
// idempotent: enrollments whose tuples already exist produce
// BackfillResult{Written: false} without error.
//
// The function does not abort on a per-enrollment failure; it processes all
// entries and returns a slice of results. Callers should inspect each
// BackfillResult.Err and log or retry failures independently.
//
// Usage:
//
//	// Enumerate existing plugin_principal enrollments across all tenants.
//	plugins := listPluginEnrollments(ctx, k8sClient)
//	results := fga.BackfillSecretResolveGrants(ctx, fgaClient, plugins)
//	for _, r := range results {
//	    if r.Err != nil {
//	        log.Error(r.Err, "backfill failed", "enrollment", r.EnrollmentUID, "tenant", r.TenantID)
//	    }
//	}
func BackfillSecretResolveGrants(ctx context.Context, fgaClient Client, plugins []PluginEnrollment) []BackfillResult {
	results := make([]BackfillResult, 0, len(plugins))
	for _, p := range plugins {
		r := BackfillResult{
			EnrollmentUID: p.EnrollmentUID,
			TenantID:      p.TenantID,
		}
		tuple := SecretCanResolveTuple(p.EnrollmentUID, p.TenantID)
		if err := fgaClient.Write(ctx, []Tuple{tuple}); err != nil {
			if errors.Is(err, clients.ErrAlreadyExists) {
				// Already exists — idempotent, not an error.
				r.Written = false
				r.Err = nil
			} else {
				r.Err = fmt.Errorf("fga: BackfillSecretResolveGrants enrollment=%s tenant=%s: %w",
					p.EnrollmentUID, p.TenantID, err)
			}
		} else {
			r.Written = true
		}
		results = append(results, r)
	}
	return results
}
