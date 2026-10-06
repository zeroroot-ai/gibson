// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package audit records each change that the tenant-operator makes to
// Kubernetes, Redis, FGA or Velero state.
//
// The operator has no audit store of its own. It sends each record to the
// daemon over DaemonOperatorService.EmitAuditEvent, and the daemon writes it
// to the Postgres audit_log through the audit-first writer (ADR-0113, D15,
// gibson#583). The actor of each record is the SPIFFE identity of the
// operator: the daemon takes it from the mTLS peer, never from the request.
//
// The order is fixed. The operator writes the record first and makes the
// change only after the daemon accepts the record. When the record cannot be
// written, the change does not happen. When the change fails after its
// record, the operator writes a second record with the result "failure" and
// the reason.
package audit

import (
	"context"
	"errors"
	"fmt"
)

// Actions of the records that the operator writes.
const (
	// ActionSagaStep is the record before a saga step changes state.
	ActionSagaStep = "operator.saga_step"
	// ActionLastBackup is the record before the last backup of a deleted
	// tenant is created (ADR-0075).
	ActionLastBackup = "operator.last_backup"
	// ActionIdentityProvision is the record before the operator creates or
	// corrects the Zitadel organization of a tenant.
	ActionIdentityProvision = "operator.identity_provision"
	// ActionIdentityDeprovision is the record before the operator deletes the
	// Zitadel organization of a tenant.
	ActionIdentityDeprovision = "operator.identity_deprovision"
	// ActionSecretsBackendProvision is the record before the operator creates
	// or corrects the OpenBao namespace of a tenant.
	ActionSecretsBackendProvision = "operator.secrets_backend_provision"
	// ActionSecretsBackendDeprovision is the record before the operator
	// deletes the OpenBao namespace of a tenant.
	ActionSecretsBackendDeprovision = "operator.secrets_backend_deprovision"
)

// ResultFailure is the result of the second record of a change that failed.
const ResultFailure = "failure"

// maxReasonChars bounds the reason of a failure record.
const maxReasonChars = 512

// Event is one audit record of a change that the operator makes.
type Event struct {
	// Action is one of the Action constants.
	Action string
	// TenantID is the tenant that owns the target.
	TenantID string
	// TargetType is the kind of the changed object, for example "tenant".
	TargetType string
	// TargetID is the id of the changed object.
	TargetID string
	// Result is empty for the record before the change, or ResultFailure.
	Result string
	// Reason is why the change failed. Set only with ResultFailure. It must
	// not hold secret material.
	Reason string
	// Fields are more facts about the change, for example the step name.
	Fields map[string]string
}

// Sink sends one record to the durable audit store. The daemon client
// (provision.EntitlementsGRPCClient) implements it.
type Sink interface {
	EmitAuditEvent(ctx context.Context, ev Event) error
}

// ErrNoSink reports a SagaEmitter built with no sink.
var ErrNoSink = errors.New("audit: the saga emitter needs a sink; the operator does not change state without an audit record")

// SagaEmitter writes the audit records of the saga steps and of the last
// backup. Build it with NewSagaEmitter.
type SagaEmitter struct {
	sink Sink
}

// NewSagaEmitter returns a SagaEmitter over sink. The sink is required.
func NewSagaEmitter(sink Sink) (*SagaEmitter, error) {
	if sink == nil {
		return nil, ErrNoSink
	}
	return &SagaEmitter{sink: sink}, nil
}

// Record writes the record of a change before the change. When it returns
// an error, the caller must not make the change.
func (e *SagaEmitter) Record(ctx context.Context, ev Event) error {
	if e == nil || e.sink == nil {
		return ErrNoSink
	}
	ev.Result = ""
	ev.Reason = ""
	if err := e.sink.EmitAuditEvent(ctx, ev); err != nil {
		return fmt.Errorf("audit: record %s of %s %q: %w", ev.Action, ev.TargetType, ev.TargetID, err)
	}
	return nil
}

// RecordFailure writes the second record of a change that failed after its
// first record. cause is the error of the change.
func (e *SagaEmitter) RecordFailure(ctx context.Context, ev Event, cause error) error {
	if e == nil || e.sink == nil {
		return ErrNoSink
	}
	ev.Result = ResultFailure
	ev.Reason = truncate(cause.Error())
	if err := e.sink.EmitAuditEvent(ctx, ev); err != nil {
		return fmt.Errorf("audit: record the failure of %s of %s %q: %w", ev.Action, ev.TargetType, ev.TargetID, err)
	}
	return nil
}

// truncate bounds a reason to maxReasonChars.
func truncate(msg string) string {
	if len(msg) <= maxReasonChars {
		return msg
	}
	return msg[:maxReasonChars] + "...[truncated]"
}
