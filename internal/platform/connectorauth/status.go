// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"sync"
	"time"
)

// RefreshStatus is the outcome of the most recent refresh attempt for one
// connector. LastError is empty when that attempt succeeded.
type RefreshStatus struct {
	LastError   string
	LastAttempt time.Time
}

// StatusBook records refresh outcomes so the status RPC can show an operator
// why a connector's token is stale — ADR-0064 requires a refresh failure to
// be visible rather than silently leaving a dying token.
//
// In-memory by choice: the durable truth is the pair of secrets, and an error
// message is diagnostic, not state. A daemon restart clears it; the next
// refresher pass repopulates it within one interval.
type StatusBook struct {
	mu sync.Mutex
	m  map[string]RefreshStatus
}

// NewStatusBook constructs an empty StatusBook.
func NewStatusBook() *StatusBook {
	return &StatusBook{m: map[string]RefreshStatus{}}
}

func statusKey(tenant, connector string) string {
	return tenant + "\x00" + connector
}

// Record stores the outcome of a refresh attempt. A nil err records success.
// The error's message is stored as-is: connectorauth errors carry the
// vendor's error code and never credential material.
func (b *StatusBook) Record(tenant, connector string, err error, at time.Time) {
	if b == nil {
		return
	}
	st := RefreshStatus{LastAttempt: at}
	if err != nil {
		st.LastError = err.Error()
	}
	b.mu.Lock()
	b.m[statusKey(tenant, connector)] = st
	b.mu.Unlock()
}

// Get returns the recorded outcome for a connector, if any.
func (b *StatusBook) Get(tenant, connector string) (RefreshStatus, bool) {
	if b == nil {
		return RefreshStatus{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.m[statusKey(tenant, connector)]
	return st, ok
}

// Clear removes a connector's record, e.g. after its grant is revoked.
func (b *StatusBook) Clear(tenant, connector string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	delete(b.m, statusKey(tenant, connector))
	b.mu.Unlock()
}
