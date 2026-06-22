/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package saga

import "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"

// ErrPermanent is re-exported from clients so saga callers can reference it
// from a single import. Use WrapPermanent to create a permanent error and
// IsPermanent to test for one.
var ErrPermanent = clients.ErrPermanent

// IsPermanent reports whether err (or any error in its chain) is ErrPermanent.
// Delegates to clients.IsPermanent.
func IsPermanent(err error) bool {
	return clients.IsPermanent(err)
}

// WrapPermanent wraps err so that both errors.Is(result, ErrPermanent) and
// errors.Is(result, err) return true. Delegates to clients.WrapPermanent.
func WrapPermanent(err error) error {
	return clients.WrapPermanent(err)
}
