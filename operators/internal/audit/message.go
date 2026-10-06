// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	operatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// MessageOf is the wire form of ev for DaemonOperatorService.EmitAuditEvent.
// Each operator daemon client sends records through it, so the mapping has
// one copy.
func MessageOf(ev Event) *operatorv1.EmitAuditEventRequest {
	return &operatorv1.EmitAuditEventRequest{
		Event: &operatorv1.AuditEventMessage{
			Type:       ev.Action,
			TenantId:   ev.TenantID,
			TargetType: ev.TargetType,
			TargetId:   ev.TargetID,
			Result:     ev.Result,
			Reason:     ev.Reason,
			Fields:     ev.Fields,
		},
	}
}
