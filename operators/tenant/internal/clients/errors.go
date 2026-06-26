// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package clients contains typed sentinel errors shared by every subsystem
// client. Concrete clients wrap these using fmt.Errorf("...: %w", ErrX) so
// reconcilers can branch with errors.Is.
package clients

import (
	"errors"
	"fmt"
)

var (
	// ErrAlreadyExists indicates the resource already exists in the
	// subsystem. Treated as success by idempotent saga steps.
	ErrAlreadyExists = errors.New("already exists")

	// ErrNotFound indicates the resource does not exist. For delete
	// operations, typically treated as success (idempotent).
	ErrNotFound = errors.New("not found")

	// ErrUnreachable indicates a transient connectivity or timeout issue.
	// Saga will retry with exponential backoff.
	ErrUnreachable = errors.New("subsystem unreachable")

	// ErrRateLimited indicates the subsystem rate-limited the request.
	// Saga will retry with longer backoff.
	ErrRateLimited = errors.New("rate limited")

	// ErrInvalidInput indicates the request was malformed. Terminal —
	// saga will not retry.
	ErrInvalidInput = errors.New("invalid input")

	// ErrConflict indicates a concurrent modification conflict.
	// Typically retriable.
	ErrConflict = errors.New("conflict")

	// ErrUnauthorized indicates auth failure. Terminal; ops must fix
	// credentials.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrPermanent is the marker error that opts a failure out of the saga's
	// transient-retry loop. Wrap an error with WrapPermanent to signal that
	// retrying will not help and the saga should set a Blocked condition and
	// stop requeuing.
	//
	// Use errors.Is(err, ErrPermanent) or clients.IsPermanent(err) to test.
	ErrPermanent = errors.New("permanent error")
)

// IsPermanent reports whether err (or any error in its chain) is ErrPermanent.
func IsPermanent(err error) bool {
	return errors.Is(err, ErrPermanent)
}

// WrapPermanent wraps err so that both errors.Is(result, ErrPermanent) and
// errors.Is(result, err) return true. Returns nil if err is nil.
func WrapPermanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}
