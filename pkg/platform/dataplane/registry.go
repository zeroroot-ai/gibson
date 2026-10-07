// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package dataplane defines platform-internal string constants that the
// gibson daemon and the tenant-operator must agree on. Constants only —
// no functions, no types beyond plain strings.
//
// Why a separate sub-package: per-tenant naming lives in
// gibson/pkg/platform/tenant; this package holds the cross-tenant /
// shared-store identifiers (Redis hash keys, Postgres database names,
// Vault key names) that don't vary per tenant. Splitting them keeps the
// tenant.Names surface focused.
package dataplane

const (
	// RedisIndexHashKey is the key (in shared Redis DB 0) of the hash that
	// maps tenant slugs to their per-tenant logical-DB index. The operator
	// HSETs into it at provision time; the daemon HGETs from it at runtime.
	//
	// Replaces the historical mismatch between operator's "tenant_db_index"
	// and daemon's "tenant:index" which produced silent provisioning
	// failures. See spec tenant-provisioning-unification Requirement 1.4.
	RedisIndexHashKey = "gibson:tenant:index"
)
