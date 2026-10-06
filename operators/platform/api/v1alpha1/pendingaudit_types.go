// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PendingAuditRecord is the audit record of a change the platform operator
// made, kept in the status of the changed resource until the daemon accepts
// it (gibson#583). The platform operator runs before the daemon exists, so a
// change cannot wait for its record: the operator makes the change, keeps the
// record here, sends it when the daemon answers, and then removes it.
type PendingAuditRecord struct {
	// Action is the audit action, for example "operator.platform_bootstrap".
	Action string `json:"action"`
	// TargetType is the kind of the changed object.
	TargetType string `json:"targetType"`
	// TargetID is the id of the changed object.
	TargetID string `json:"targetID"`
	// Result is empty for the record of a change, or "failure".
	// +optional
	Result string `json:"result,omitempty"`
	// Reason is why the change failed.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Fields are more facts about the change.
	// +optional
	Fields map[string]string `json:"fields,omitempty"`
	// Count is how many records an overflow record stands for. The pending
	// list has a fixed size, and one overflow record at its end counts the
	// records that did not fit.
	// +optional
	Count int32 `json:"count,omitempty"`
	// FirstAt is when the operator first made this record.
	FirstAt metav1.Time `json:"firstAt"`
}
