// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
)

type fixedGrant string

func (g fixedGrant) Grant(context.Context, modelclient.Caller) (string, error) { return string(g), nil }

func routedClient(t *testing.T, status func(n int32) int) (*modelclient.Client, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		code := status(atomic.AddInt32(&calls, 1))
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(`{"id":"r1","output":[]}`))
			return
		}
		_, _ = w.Write([]byte("route not found"))
	}))
	t.Cleanup(srv.Close)
	c, err := modelclient.New(modelclient.Config{BaseURL: srv.URL, Grants: fixedGrant("g")})
	require.NoError(t, err)
	return c, &calls
}

func routedCall(t *testing.T, c *modelclient.Client, timeout time.Duration) error {
	t.Helper()
	_, err := RespondWhenRouted(context.Background(), c,
		modelclient.Caller{Tenant: "t", Task: "w"}, modelclient.Target{Tenant: "t", Provider: "p", Model: "m"},
		modelclient.Request{Input: []modelclient.Item{modelclient.UserMessage("hi")}}, timeout)
	return err
}

// A 404 is the route that the operator has not rendered yet. The call waits and then succeeds.
func TestRespondWhenRouted_WaitsForTheRoute(t *testing.T) {
	c, calls := routedClient(t, func(n int32) int {
		if n < 2 {
			return http.StatusNotFound
		}
		return http.StatusOK
	})
	require.NoError(t, routedCall(t, c, 10*time.Second))
	require.EqualValues(t, 2, atomic.LoadInt32(calls))
}

// A refusal is not retried.
func TestRespondWhenRouted_ReturnsARefusalAtOnce(t *testing.T) {
	c, calls := routedClient(t, func(int32) int { return http.StatusForbidden })
	require.Error(t, routedCall(t, c, 10*time.Second))
	require.EqualValues(t, 1, atomic.LoadInt32(calls))
}

// A route that never appears ends with the last error after the timeout.
func TestRespondWhenRouted_GivesUpAfterTheTimeout(t *testing.T) {
	c, _ := routedClient(t, func(int32) int { return http.StatusNotFound })
	err := routedCall(t, c, 1500*time.Millisecond)
	require.ErrorContains(t, err, "no route after")
}
