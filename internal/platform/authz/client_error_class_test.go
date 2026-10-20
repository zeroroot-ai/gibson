// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

// TestMapSDKError_StatusDecidesTheClass proves that an FGA status code decides
// whether an error is permanent or an outage. A bad token or a wrong store ID
// must not read as an outage, because a caller retries an outage with no end.
func TestMapSDKError_StatusDecidesTheClass(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		want      error
		retryable bool
	}{
		{http.StatusBadRequest, `{"code":"validation_error","message":"bad"}`, ErrInvalidArgument, false},
		{http.StatusUnauthorized, `{"code":"auth_failed","message":"bad token"}`, ErrFgaUnauthenticated, false},
		{http.StatusForbidden, `{"code":"forbidden","message":"no"}`, ErrFgaUnauthenticated, false},
		{http.StatusNotFound, `{"code":"store_id_not_found","message":"no store"}`, ErrFgaNotFound, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			capture := &capturedWrite{}
			srv := fgaWriteServer(t, tc.status, tc.body, capture)
			defer srv.Close()

			az := newTestFgaAuthorizer(t, srv.URL)
			err := az.WriteConditional(context.Background(), ConditionalTuple{
				User: "user:alice", Relation: "active_session", Object: "tenant:acme",
				ConditionName: "token_not_revoked", ConditionContext: map[string]any{"revoked_at": EpochRevokedAt},
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d: want %v, got %v", tc.status, tc.want, err)
			}
			if errors.Is(err, ErrFgaUnavailable) || errors.Is(err, ErrFgaTimeout) {
				t.Fatalf("status %d: a permanent error must not read as an outage: %v", tc.status, err)
			}
		})
	}
}

// TestMapSDKError_TransportStaysAnOutage proves that a deadline is a timeout,
// that an unknown error is an outage, and that the word timeout in a message
// does not make a timeout.
func TestMapSDKError_TransportStaysAnOutage(t *testing.T) {
	if err := mapSDKError(fmt.Errorf("call: %w", context.DeadlineExceeded)); !errors.Is(err, ErrFgaTimeout) {
		t.Errorf("a deadline must be ErrFgaTimeout, got %v", err)
	}
	if err := mapSDKError(errors.New("dial tcp: connection refused")); !errors.Is(err, ErrFgaUnavailable) {
		t.Errorf("a refused connection must be ErrFgaUnavailable, got %v", err)
	}
	err := mapSDKError(errors.New("the store has no timeout set"))
	if !errors.Is(err, ErrFgaUnavailable) || errors.Is(err, ErrFgaTimeout) {
		t.Errorf("the word timeout alone must not make a timeout, got %v", err)
	}
	if err := mapSDKError(nil); err != nil {
		t.Errorf("nil must map to nil, got %v", err)
	}
}
