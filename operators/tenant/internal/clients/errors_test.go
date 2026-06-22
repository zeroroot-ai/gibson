/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package clients_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

func TestErrorsSentinel_Is(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"AlreadyExists wrapped", fmt.Errorf("wrapped: %w", clients.ErrAlreadyExists), clients.ErrAlreadyExists},
		{"NotFound wrapped", fmt.Errorf("orgSlug=acme: %w", clients.ErrNotFound), clients.ErrNotFound},
		{"Unreachable", clients.ErrUnreachable, clients.ErrUnreachable},
		{"RateLimited wrapped", fmt.Errorf("stripe 429: %w", clients.ErrRateLimited), clients.ErrRateLimited},
		{"InvalidInput", clients.ErrInvalidInput, clients.ErrInvalidInput},
		{"Conflict", clients.ErrConflict, clients.ErrConflict},
		{"Unauthorized", clients.ErrUnauthorized, clients.ErrUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.want) {
				t.Errorf("errors.Is failed: %v vs %v", tc.err, tc.want)
			}
		})
	}
}
