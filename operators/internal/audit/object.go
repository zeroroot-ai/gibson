// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AnnotationCorrelationID holds the id of the daemon audit record of the
// human request that created or changed a tenant resource. The operator
// copies the id from the daemon queue entry onto the resource, and each
// operator record of that resource carries it as its correlation id. A
// resource with no such annotation was not started by a recorded human
// request: its records name the operator as the only actor.
const AnnotationCorrelationID = "gibson.zeroroot.ai/correlation-id"

// FieldCorrelationID is the record field that holds the correlation id.
const FieldCorrelationID = "correlation_id"

// recordTimeout bounds one audit record, so a daemon that does not answer
// holds the reconcile for a bounded time.
const recordTimeout = 10 * time.Second

// CorrelationIDOf returns the correlation id stamped on obj, or "".
func CorrelationIDOf(obj client.Object) string {
	return obj.GetAnnotations()[AnnotationCorrelationID]
}

// ObjectEvent returns the record of a change to obj. The record names the
// tenant that owns obj, obj as the target and the correlation id stamped on
// obj. fields are added to the record.
func ObjectEvent(action string, obj client.Object, fields map[string]string) Event {
	targetID := obj.GetName()
	if ns := obj.GetNamespace(); ns != "" {
		targetID = ns + "/" + obj.GetName()
	}
	all := make(map[string]string, len(fields)+1)
	for k, v := range fields {
		all[k] = v
	}
	if id := CorrelationIDOf(obj); id != "" {
		all[FieldCorrelationID] = id
	}
	return Event{
		Action:     action,
		TenantID:   tenantOf(obj),
		TargetType: targetTypeOf(obj),
		TargetID:   targetID,
		Fields:     all,
	}
}

// ErrNotRecorded reports a change that did not run because its audit record
// was not written.
var ErrNotRecorded = errors.New("audit: the record was not written; nothing changed")

// Change writes the record of ev, then runs change. When the record is not
// written, change does not run. When change fails, Change writes a second
// record with the result "failure" and the reason, and returns the error of
// change.
//
// When the first record is not written, the error wraps ErrNotRecorded, so a
// caller can tell "nothing changed" from "the change failed".
func (e *SagaEmitter) Change(ctx context.Context, ev Event, change func() error) error {
	if err := e.bounded(ctx, func(rctx context.Context) error { return e.Record(rctx, ev) }); err != nil {
		return fmt.Errorf("%w: %w", ErrNotRecorded, err)
	}
	err := change()
	if err == nil {
		return nil
	}
	if ferr := e.bounded(ctx, func(rctx context.Context) error { return e.RecordFailure(rctx, ev, err) }); ferr != nil {
		return errors.Join(err, ferr)
	}
	return err
}

// bounded runs one audit write under its own deadline.
func (e *SagaEmitter) bounded(ctx context.Context, write func(context.Context) error) error {
	rctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()
	return write(rctx)
}

// tenantOf returns the tenant that owns obj. A Tenant is cluster scoped and
// its name is the tenant id. A namespaced object belongs to the Tenant of its
// owner reference, or else to the tenant of its "tenant-<id>" namespace.
func tenantOf(obj client.Object) string {
	ns := obj.GetNamespace()
	if ns == "" {
		return obj.GetName()
	}
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Tenant" && ref.Name != "" {
			return ref.Name
		}
	}
	return strings.TrimPrefix(ns, "tenant-")
}

// targetTypeOf is the kind of obj in lower case, for example "tenant". A
// typed object read through a client often has no kind set, so the Go type
// name stands in.
func targetTypeOf(obj client.Object) string {
	if k := obj.GetObjectKind().GroupVersionKind().Kind; k != "" {
		return strings.ToLower(k)
	}
	t := reflect.TypeOf(obj)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return strings.ToLower(t.Name())
}
