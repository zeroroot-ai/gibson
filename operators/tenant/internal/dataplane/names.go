/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// names.go consolidates per-tenant resource naming + KEK derivation by
// delegating to github.com/zeroroot-ai/gibson/pkg/platform/tenant. The
// operator and the gibson daemon share that package; this file exists
// only as a string-input adapter for the operator's existing string-
// based call sites and to keep the dataplane.KEKInitProvisioner type
// reachable from cmd/main.go's wiring.
//
// Spec: tenant-provisioning-unification (Phase 2 task 2.1).

package dataplane

import (
	"context"
	"fmt"

	gtenant "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
	"github.com/zeroroot-ai/sdk/auth"
)

// sanitizeTenantID returns the canonical Redis index field form of the
// tenant ID — the slug (hyphens preserved), as used by the daemon when
// looking up the master index hash (HGET gibson:tenant:index <slug>).
//
// The daemon calls auth.TenantID.String() for the hash field, which
// preserves the original slug. Using Underscore() here would write
// "zero_root" while the daemon reads "zero-root", causing a permanent
// FailedPrecondition on every API call for hyphenated tenant names.
// See: tenant-operator#<filed-below>.
func sanitizeTenantID(tenantID string) (string, error) {
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return "", fmt.Errorf("dataplane: %w", err)
	}
	return gtenant.FromTenantID(id).RedisIndexField(), nil
}

// tenantDBName returns the per-tenant Postgres database / Qdrant
// collection name: "tenant_<underscore>". Source of truth:
// gtenant.Names.PostgresDB().
func tenantDBName(tenantID string) (string, error) {
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return "", fmt.Errorf("dataplane: %w", err)
	}
	return gtenant.FromTenantID(id).PostgresDB(), nil
}

// tenantNames returns the gtenant.Names value for tenantID. Call sites
// that need more than one per-tenant name (e.g. neo4j.go needs the
// StatefulSet, Service, and Secret names) should use this once and call
// methods, rather than re-validating + string-concatenating each name.
// Source of truth for every per-tenant K8s object name —
// tenant-operator#84.
func tenantNames(tenantID string) (gtenant.Names, error) {
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return gtenant.Names{}, fmt.Errorf("dataplane: %w", err)
	}
	return gtenant.FromTenantID(id), nil
}

// tenantRolePasswordVia derives the Postgres role password using the
// supplied KEKDeriver. Callers pass a vaultTransitDeriver or
// kmsHMACDeriver so the master KEK never enters the operator's process
// memory. The returned string is zeroized only via Go's garbage
// collection — but the underlying KEK bytes are zeroized explicitly.
func tenantRolePasswordVia(ctx context.Context, deriver KEKDeriver, tenantID string) (string, error) {
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return "", fmt.Errorf("dataplane/kek: %w", err)
	}
	kek, err := deriver.DeriveTenantKEK(ctx, id)
	if err != nil {
		return "", err
	}
	defer gtenant.Zeroize(kek)
	return gtenant.PostgresPasswordFromKEK(kek)
}

// KEKInitProvisioner is a marker step in the dataplane pipeline that
// validates per-tenant KEK derivation works for a tenant ID. Real KEK
// material is baked into the Postgres role password by pgProvisioner;
// this step exists for status-condition reporting and as the future
// home for KEK rotation flows.
type KEKInitProvisioner struct {
	// KEKDeriver derives the per-tenant KEK. Required.
	KEKDeriver KEKDeriver
}

// Provision verifies the deriver can produce a per-tenant KEK for the
// given tenant. Derived bytes are zeroized immediately — this step
// does not persist any secret material itself.
func (k *KEKInitProvisioner) Provision(ctx context.Context, tenantID string) error {
	if k.KEKDeriver == nil {
		return fmt.Errorf("dataplane/kek: KEKDeriver required")
	}
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return fmt.Errorf("dataplane/kek: %w", err)
	}
	kek, err := k.KEKDeriver.DeriveTenantKEK(ctx, id)
	if err != nil {
		return err
	}
	gtenant.Zeroize(kek)
	return nil
}

// Deprovision is a no-op: there is no persistent KEK material to remove.
func (k *KEKInitProvisioner) Deprovision(_ context.Context, _ string) error {
	return nil
}
