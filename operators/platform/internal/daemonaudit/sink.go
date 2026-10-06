// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemonaudit is the platform operator's path for audit records to
// the daemon (gibson#583).
//
// The platform operator starts before the daemon and before the SPIRE agent
// can give it an identity, so it never dials at boot: a dial that waited for
// either would deadlock the install. The Sink dials on the first record and
// again after each failed dial. A record that cannot be sent stays pending in
// the status of its resource (internal/controller/pending_audit.go).
package daemonaudit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
)

// DialFunc opens the connection to the daemon. Production uses Dial; tests
// pass a fake.
type DialFunc func(ctx context.Context) (operatorv1.DaemonOperatorServiceClient, func() error, error)

// Sink sends audit records to the daemon over SPIFFE mTLS. It implements
// audit.Sink.
type Sink struct {
	dial DialFunc

	mu     sync.Mutex
	client operatorv1.DaemonOperatorServiceClient
	close  func() error
}

var _ audit.Sink = (*Sink)(nil)

// Settings reads the daemon address and SPIFFE id from the environment. Both
// are required: no code holds the trust domain of the install (ADR-0164).
func Settings(getenv func(string) string) (addr, svid string, err error) {
	addr = strings.TrimSpace(getenv("GIBSON_DAEMON_GRPC_ADDRESS"))
	svid = strings.TrimSpace(getenv("GIBSON_DAEMON_SPIFFE_ID"))
	if addr == "" || svid == "" {
		return "", "", errors.New("GIBSON_DAEMON_GRPC_ADDRESS and GIBSON_DAEMON_SPIFFE_ID are required: the platform operator sends its audit records to the daemon (gibson#583)")
	}
	return addr, svid, nil
}

// Dial returns the production DialFunc for the daemon at addr with the
// SPIFFE id svid.
func Dial(addr, svid string) DialFunc {
	return func(ctx context.Context) (operatorv1.DaemonOperatorServiceClient, func() error, error) {
		c, err := daemontransport.NewClient(ctx, daemontransport.Options{Addr: addr, DaemonSVID: svid})
		if err != nil {
			return nil, nil, fmt.Errorf("daemonaudit: dial: %w", err)
		}
		return operatorv1.NewDaemonOperatorServiceClient(c.Conn()), c.Close, nil
	}
}

// New returns a Sink that dials with dial on first use.
func New(dial DialFunc) (*Sink, error) {
	if dial == nil {
		return nil, errors.New("daemonaudit: a dial function is required")
	}
	return &Sink{dial: dial}, nil
}

// EmitAuditEvent sends one record. A failed dial is returned and retried on
// the next record.
func (s *Sink) EmitAuditEvent(ctx context.Context, ev audit.Event) error {
	c, err := s.connected(ctx)
	if err != nil {
		return err
	}
	if _, err := c.EmitAuditEvent(ctx, audit.MessageOf(ev)); err != nil {
		return fmt.Errorf("daemonaudit: emit %s: %w", ev.Action, err)
	}
	return nil
}

// connected returns the client, and dials when there is none.
func (s *Sink) connected(ctx context.Context) (operatorv1.DaemonOperatorServiceClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	c, closeFn, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	s.client, s.close = c, closeFn
	return c, nil
}

// Close releases the connection, when there is one.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.close == nil {
		return nil
	}
	err := s.close()
	s.client, s.close = nil, nil
	return err
}
