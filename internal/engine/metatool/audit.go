// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package metatool

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// Audit names of a connector tool call. The action is the one name that a
// reader of the audit trail filters on. The resource is the connector.
const (
	AuditAction   = "connector.tool.call"
	AuditResource = "connector"

	// AuditIntent is the result of the record that is written before the call.
	AuditIntent = "intent"
)

// AuditRecorder writes the two audit records of a call through the audit
// logger of the daemon. The actor is the identity on the context.
type AuditRecorder struct {
	Log *audit.AuditLogger
}

// Intent writes the record that comes before the call. An error means that the
// record is not durable, and the call must not happen.
func (a AuditRecorder) Intent(ctx context.Context, rec CallRecord) error {
	if a.Log == nil {
		return errors.New("the audit log is not wired")
	}
	if _, err := a.Log.RecordWithResult(ctx, AuditAction, AuditResource, rec.Connector, AuditIntent, auditDetails(rec, nil)); err != nil {
		return fmt.Errorf("write the intent record: %w", err)
	}
	return nil
}

// Result writes the record of the outcome. It reports the error of the write to
// the caller, which logs it: the call has happened already.
func (a AuditRecorder) Result(ctx context.Context, rec CallRecord, callErr error) error {
	if a.Log == nil {
		return errors.New("the audit log is not wired")
	}
	result := "success"
	if callErr != nil {
		result = "failure"
	}
	if _, err := a.Log.RecordWithResult(ctx, AuditAction, AuditResource, rec.Connector, result, auditDetails(rec, callErr)); err != nil {
		return fmt.Errorf("write the result record: %w", err)
	}
	return nil
}

func auditDetails(rec CallRecord, callErr error) map[string]any {
	d := map[string]any{"tool": rec.Tool}
	if rec.WorkID != "" {
		d["work_id"] = rec.WorkID
	}
	if rec.MissionID != "" {
		d["mission_id"] = rec.MissionID
	}
	if callErr != nil {
		d["error"] = errorClass(callErr)
	}
	return d
}

// errorClass names why a call failed without the text of the error, which can
// hold what the connector returned.
func errorClass(err error) string {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrBlocked):
		return "blocked"
	default:
		return "failed"
	}
}
