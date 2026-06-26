// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package zitadel is platform-operator's internal Zitadel admin client.
// Vendored from tenant-operator/internal/clients/zitadel/ rather than
// shared via the public SDK — infrastructure clients are not customer
// surface (see root CLAUDE.md "SDK is customer-releasable OSS;
// infrastructure code is forbidden").
//
// This copy carries the OIDC-client + project minting methods the
// platform-operator's OIDCClient reconciler needs. Tenant-operator's
// copy carries the tenant-lifecycle methods (CreateOrganization,
// AddMember, etc.). The two are intentionally separate — there is
// almost no method overlap.
package zitadel

import (
	"errors"
	"fmt"
)

// Sentinel errors for idempotent saga steps to branch on via errors.Is.
var (
	ErrAlreadyExists = errors.New("already exists")
	ErrNotFound      = errors.New("not found")
	ErrUnreachable   = errors.New("subsystem unreachable")
	ErrRateLimited   = errors.New("rate limited")
	ErrInvalidInput  = errors.New("invalid input")
	ErrConflict      = errors.New("conflict")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrPermanent     = errors.New("permanent error")
)

// IsPermanent reports whether err wraps ErrPermanent — opts a failure
// out of the reconciler's transient-retry loop.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent)
}

// WrapPermanent wraps err so both errors.Is(result, ErrPermanent) and
// errors.Is(result, err) return true. Returns nil if err is nil.
func WrapPermanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

// IsNotFound / IsAlreadyExists / IsConflict are convenience predicates.
func IsNotFound(err error) bool      { return errors.Is(err, ErrNotFound) }
func IsAlreadyExists(err error) bool { return errors.Is(err, ErrAlreadyExists) }
func IsConflict(err error) bool      { return errors.Is(err, ErrConflict) }
