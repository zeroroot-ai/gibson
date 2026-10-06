// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"sync/atomic"

	"github.com/zeroroot-ai/sdk/auth"
)

// fakeProbe is a hand-written test fake for DataPlaneProbe. It records the
// number of calls per method (so we can assert cache behaviour) and lets
// the test set arbitrary return values per call.
type fakeProbe struct {
	brokerExists bool
	brokerErr    error
	pingable     bool
	pingErr      error

	brokerCalls atomic.Int64
	pingCalls   atomic.Int64
}

func (f *fakeProbe) BrokerConfigExists(_ context.Context, _ auth.TenantID) (bool, error) {
	f.brokerCalls.Add(1)
	return f.brokerExists, f.brokerErr
}

func (f *fakeProbe) Pingable(_ context.Context, _ auth.TenantID) (bool, error) {
	f.pingCalls.Add(1)
	return f.pingable, f.pingErr
}
