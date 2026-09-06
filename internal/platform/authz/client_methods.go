// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"fmt"
	"time"

	fgasdk "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Check returns true if the given user has the given relation on the given object.
//
// The call is wrapped in an OTel span "gibson.authz.fga_check" with attributes
// user, relation, object, result, and duration_ms. Input validation happens
// before any network call — empty user, relation, or object returns ErrInvalidArgument.
func (f *fgaAuthorizer) Check(ctx context.Context, user, relation, object string) (bool, error) {
	// Input validation — no FGA call for invalid inputs.
	if user == "" || relation == "" || object == "" {
		return false, newInvalidArgumentError(
			fmt.Sprintf("Check: user=%q relation=%q object=%q — all fields must be non-empty", user, relation, object),
		)
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanCheck,
		attribute.String("authz.user", user),
		attribute.String("authz.relation", relation),
		attribute.String("authz.object", object),
	)
	defer span.End()

	// Apply per-call timeout.
	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	resp, err := f.client.Check(callCtx).Body(fgaclient.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "Check")
		return false, typedErr
	}

	allowed := resp.GetAllowed()
	span.SetAttributes(attribute.Bool("authz.result", allowed))
	span.SetStatus(codes.Ok, "")

	f.logger.Debug("authz: Check",
		"user", user,
		"relation", relation,
		"object", object,
		"allowed", allowed,
		"duration_ms", durationMs,
	)

	return allowed, nil
}

// BatchCheck evaluates multiple authorization checks in a single FGA API call.
//
// Each check is emitted under the "gibson.authz.fga_batch_check" span.
// Results are returned in the same order as the input checks slice.
func (f *fgaAuthorizer) BatchCheck(ctx context.Context, checks []CheckRequest) ([]bool, error) {
	if len(checks) == 0 {
		return []bool{}, nil
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanBatchCheck,
		attribute.Int("authz.check_count", len(checks)),
	)
	defer span.End()

	// Apply per-call timeout.
	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	// Build the SDK request items.
	items := make([]fgaclient.ClientCheckRequest, len(checks))
	for i, c := range checks {
		items[i] = fgaclient.ClientCheckRequest{
			User:     c.User,
			Relation: c.Relation,
			Object:   c.Object,
		}
	}

	batchResp, err := f.client.ClientBatchCheck(callCtx).Body(items).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "BatchCheck")
		return nil, typedErr
	}

	results := make([]bool, len(checks))
	for i, r := range *batchResp {
		if r.Error != nil {
			// Individual check error: treat as denied (fail-closed per item).
			results[i] = false
		} else {
			results[i] = r.GetAllowed()
		}
	}

	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: BatchCheck",
		"check_count", len(checks),
		"duration_ms", durationMs,
	)

	return results, nil
}

// Write creates or updates one or more relationship tuples in FGA.
//
// All tuples are submitted in a single API call. Wrapped in span "gibson.authz.fga_write".
func (f *fgaAuthorizer) Write(ctx context.Context, tuples []Tuple) error {
	if len(tuples) == 0 {
		return nil
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanWrite,
		attribute.Int("authz.tuple_count", len(tuples)),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	writes := make([]fgaclient.ClientTupleKey, len(tuples))
	for i, t := range tuples {
		writes[i] = fgaclient.ClientTupleKey{
			User:     t.User,
			Relation: t.Relation,
			Object:   t.Object,
		}
	}

	_, err := f.client.WriteTuples(callCtx).Body(writes).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		// OpenFGA's batched write is one transaction: when ANY tuple in the
		// batch already exists it fails the whole batch with "cannot write a
		// tuple which already exists" and writes nothing. The interface
		// contract is per-tuple idempotency, so on that error find the tuples
		// that are still missing and write only those. Treating the error as
		// a no-op for the whole batch silently dropped every new tuple when
		// one old one was present (a re-enrolled identity ended up with no
		// tuples at all).
		if isAlreadyExistsError(err) {
			return f.writeMissing(spanCtx, span, tuples, durationMs)
		}
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "Write")
		return typedErr
	}

	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: Write",
		"tuple_count", len(tuples),
		"duration_ms", durationMs,
	)

	return nil
}

// writeMissing is the already-exists branch of Write: it reads each tuple by
// exact key, then writes the subset that is absent. No absent tuple means
// the whole batch was a retry of an applied write, a no-op.
func (f *fgaAuthorizer) writeMissing(ctx context.Context, span trace.Span, tuples []Tuple, firstAttemptMs int64) error {
	missing := make([]Tuple, 0, len(tuples))
	for _, t := range tuples {
		existing, err := f.ReadTuples(ctx, t.User, t.Relation, t.Object)
		if err != nil {
			f.recordSpanError(span, err, "Write")
			return fmt.Errorf("authz: Write: read back %s#%s@%s: %w", t.Object, t.Relation, t.User, err)
		}
		if len(existing) == 0 {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		span.SetStatus(codes.Ok, "")
		f.logger.Debug("authz: Write (no-op, tuples already exist)",
			"tuple_count", len(tuples),
			"duration_ms", firstAttemptMs,
		)
		return nil
	}
	writes := make([]fgaclient.ClientTupleKey, len(missing))
	for i, t := range missing {
		writes[i] = fgaclient.ClientTupleKey{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	callCtx, cancel := f.callContext(ctx)
	defer cancel()
	if _, err := f.client.WriteTuples(callCtx).Body(writes).Execute(); err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "Write")
		return typedErr
	}
	span.SetAttributes(attribute.Int("authz.tuples_written_after_conflict", len(missing)))
	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: Write (partial batch existed; wrote the rest)",
		"tuple_count", len(tuples),
		"written", len(missing),
	)
	return nil
}

// Delete removes one or more relationship tuples from FGA.
//
// All tuples are submitted in a single API call. Wrapped in span "gibson.authz.fga_delete".
func (f *fgaAuthorizer) Delete(ctx context.Context, tuples []Tuple) error {
	if len(tuples) == 0 {
		return nil
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanDelete,
		attribute.Int("authz.tuple_count", len(tuples)),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	deletes := make([]fgaclient.ClientTupleKeyWithoutCondition, len(tuples))
	for i, t := range tuples {
		deletes[i] = fgaclient.ClientTupleKeyWithoutCondition{
			User:     t.User,
			Relation: t.Relation,
			Object:   t.Object,
		}
	}

	_, err := f.client.DeleteTuples(callCtx).Body(deletes).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "Delete")
		return typedErr
	}

	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: Delete",
		"tuple_count", len(tuples),
		"duration_ms", durationMs,
	)

	return nil
}

// ListObjects returns the IDs of all objects of the given type for which
// the given user has the given relation.
//
// Wrapped in span "gibson.authz.fga_list_objects".
func (f *fgaAuthorizer) ListObjects(ctx context.Context, user, relation, objectType string) ([]string, error) {
	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanListObjects,
		attribute.String("authz.user", user),
		attribute.String("authz.relation", relation),
		attribute.String("authz.object_type", objectType),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	resp, err := f.client.ListObjects(callCtx).Body(fgaclient.ClientListObjectsRequest{
		User:     user,
		Relation: relation,
		Type:     objectType,
	}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "ListObjects")
		return nil, typedErr
	}

	objects := resp.GetObjects()
	span.SetAttributes(attribute.Int("authz.result_count", len(objects)))
	span.SetStatus(codes.Ok, "")

	f.logger.Debug("authz: ListObjects",
		"user", user,
		"relation", relation,
		"object_type", objectType,
		"result_count", len(objects),
		"duration_ms", durationMs,
	)

	return objects, nil
}

// ListUsers returns the user references that have the given relation on the given object.
//
// objectType and object together identify the FGA object.
// Wrapped in span "gibson.authz.fga_list_users".
//
// ListUsers hardcodes the returned subject type to "user" (see UserFilters
// below), and refuses up front any relation model.fga says cannot yield a
// "user" subject.
//
// The refusal is the control, not a nicety. Verified against OpenFGA's own
// resolver (pkg/server/commands/listusers): a UserFilter type the relation
// does not admit is NOT a request-level validation error — OpenFGA finds no
// possible edges for that type and returns a normal, successful, EMPTY user
// list. Nothing in the wire response distinguishes that from "the relation
// genuinely has zero holders right now", so a guard that reads an empty list
// as "nobody holds this" passes unconditionally. Two guards in this repo
// shipped exactly that way (team.parent: [tenant] being the live one).
//
// Since the answer is not in the response, it is taken from the model:
// requireSubjectType resolves model.fga (embedded, see model_subject_types.go)
// and returns an ErrInvalidArgument-class error before the call goes out. A
// caller must handle an error; a caller silently believes an empty slice.
//
// Note that "admits user" follows usersets, so it is broader than the
// relation's literal bracket list — component.team_write_disabled is declared
// [team#member] yet DOES admit "user", because team#member expands to users.
// Use ListUsersOfType when you want the subjects at some other type.
func (f *fgaAuthorizer) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
	if err := requireSubjectType(objectType, relation, "user"); err != nil {
		return nil, err
	}
	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanListUsers,
		attribute.String("authz.object_type", objectType),
		attribute.String("authz.object", object),
		attribute.String("authz.relation", relation),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	resp, err := f.client.ListUsers(callCtx).Body(fgaclient.ClientListUsersRequest{
		Object: fgasdk.FgaObject{
			Type: objectType,
			Id:   extractID(object),
		},
		Relation: relation,
		UserFilters: []fgasdk.UserTypeFilter{
			{Type: "user"},
		},
	}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "ListUsers")
		return nil, typedErr
	}

	var userRefs []string
	for _, u := range resp.GetUsers() {
		if _, ok := u.GetObjectOk(); ok {
			obj := u.GetObject()
			userRefs = append(userRefs, obj.GetType()+":"+obj.GetId())
		}
	}

	span.SetAttributes(attribute.Int("authz.result_count", len(userRefs)))
	span.SetStatus(codes.Ok, "")

	// An empty result used to be logged at WARN because it was ambiguous:
	// it could mean "nobody holds this" or "this query could never match".
	// requireSubjectType has already ruled out the second reading, so zero
	// now means zero and the WARN would point readers at a cause that the
	// guard makes impossible. A log line was never the control anyway — the
	// refusal above is.
	f.logger.Debug("authz: ListUsers",
		"object_type", objectType,
		"object", object,
		"relation", relation,
		"result_count", len(userRefs),
		"duration_ms", durationMs,
	)

	return userRefs, nil
}

// ListUsersOfType is like ListUsers but constrains the returned user references
// to a single FGA user type — the tenants under system_tenant#parent, say, or
// under team#parent.
//
// CORRECTION (this comment used to claim the opposite, and that contradiction
// with ListUsers' own doc is what let a guard ship against an always-empty
// query): OpenFGA does NOT error when a user-filter type is one the relation
// does not admit. It reports an error only for a type the model does not
// declare at all; a declared-but-unreachable type yields a successful, empty
// list. So neither this method nor ListUsers can rely on the server to catch a
// mistyped listing, and both call requireSubjectType to resolve the question
// from the embedded model.fga before the call goes out. See
// model_subject_types.go.
//
// objectType and object together identify the FGA object; userType is the FGA
// type of the desired user references (e.g. "tenant"). Returned references are
// fully qualified ("<userType>:<id>").
func (f *fgaAuthorizer) ListUsersOfType(ctx context.Context, objectType, object, relation, userType string) ([]string, error) {
	if err := requireSubjectType(objectType, relation, userType); err != nil {
		return nil, err
	}
	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanListUsers,
		attribute.String("authz.object_type", objectType),
		attribute.String("authz.object", object),
		attribute.String("authz.relation", relation),
		attribute.String("authz.user_type", userType),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	resp, err := f.client.ListUsers(callCtx).Body(fgaclient.ClientListUsersRequest{
		Object: fgasdk.FgaObject{
			Type: objectType,
			Id:   extractID(object),
		},
		Relation: relation,
		UserFilters: []fgasdk.UserTypeFilter{
			{Type: userType},
		},
	}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "ListUsersOfType")
		return nil, typedErr
	}

	var userRefs []string
	for _, u := range resp.GetUsers() {
		if _, ok := u.GetObjectOk(); ok {
			obj := u.GetObject()
			userRefs = append(userRefs, obj.GetType()+":"+obj.GetId())
		}
	}

	span.SetAttributes(attribute.Int("authz.result_count", len(userRefs)))
	span.SetStatus(codes.Ok, "")

	f.logger.Debug("authz: ListUsersOfType",
		"object_type", objectType,
		"object", object,
		"relation", relation,
		"user_type", userType,
		"result_count", len(userRefs),
		"duration_ms", durationMs,
	)

	return userRefs, nil
}

// WriteConditional writes a single condition-bearing FGA relationship tuple.
//
// OpenFGA represents a conditioned tuple as a TupleKey with a Condition field
// carrying the condition name and a context map. The write is idempotent: if an
// identical (user, relation, object, condition, context) tuple already exists,
// the call returns nil.
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
func (f *fgaAuthorizer) WriteConditional(ctx context.Context, t ConditionalTuple) error {
	if t.User == "" || t.Relation == "" || t.Object == "" || t.ConditionName == "" {
		return newInvalidArgumentError(
			fmt.Sprintf("WriteConditional: user=%q relation=%q object=%q conditionName=%q — all fields must be non-empty",
				t.User, t.Relation, t.Object, t.ConditionName),
		)
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanWrite,
		attribute.String("authz.user", t.User),
		attribute.String("authz.relation", t.Relation),
		attribute.String("authz.object", t.Object),
		attribute.String("authz.condition", t.ConditionName),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	tk := fgaclient.ClientTupleKey{
		User:     t.User,
		Relation: t.Relation,
		Object:   t.Object,
		Condition: &fgasdk.RelationshipCondition{
			Name:    t.ConditionName,
			Context: conditionContextPtr(t.ConditionContext),
		},
	}

	_, err := f.client.WriteTuples(callCtx).Body([]fgaclient.ClientTupleKey{tk}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		if isAlreadyExistsError(err) {
			span.SetStatus(codes.Ok, "")
			f.logger.Debug("authz: WriteConditional (no-op, tuple already exists)",
				"user", t.User, "relation", t.Relation, "object", t.Object,
				"condition", t.ConditionName, "duration_ms", durationMs,
			)
			return nil
		}
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "WriteConditional")
		return typedErr
	}

	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: WriteConditional",
		"user", t.User, "relation", t.Relation, "object", t.Object,
		"condition", t.ConditionName, "duration_ms", durationMs,
	)
	return nil
}

// UpdateConditionalTuple atomically replaces a conditioned tuple's context
// by issuing a delete+write in a single FGA WriteRequest.
//
// OpenFGA has no in-place update for tuple context: the old conditioned tuple
// must be deleted (via the TupleKeyWithoutCondition shape) and the new one
// must be written in the same transaction. Both operations are included in a
// single Write call so the store never sees a gap.
//
// If the existing tuple is absent (pre-backfill state), the delete portion
// of the WriteRequest returns "tuple to be deleted did not exist". In that
// case UpdateConditionalTuple falls back to a plain WriteConditional so
// callers — including RevokeUserSessions — never need to distinguish between
// "first write" and "update".
//
// Spec: instant-session-revocation (gibson#627 Slice 2).
func (f *fgaAuthorizer) UpdateConditionalTuple(ctx context.Context, t ConditionalTuple) error {
	if t.User == "" || t.Relation == "" || t.Object == "" || t.ConditionName == "" {
		return newInvalidArgumentError(
			fmt.Sprintf("UpdateConditionalTuple: user=%q relation=%q object=%q conditionName=%q — all fields must be non-empty",
				t.User, t.Relation, t.Object, t.ConditionName),
		)
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanWrite,
		attribute.String("authz.user", t.User),
		attribute.String("authz.relation", t.Relation),
		attribute.String("authz.object", t.Object),
		attribute.String("authz.condition", t.ConditionName),
		attribute.String("authz.op", "update_conditional"),
	)
	defer span.End()

	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()

	writeKey := fgaclient.ClientTupleKey{
		User:     t.User,
		Relation: t.Relation,
		Object:   t.Object,
		Condition: &fgasdk.RelationshipCondition{
			Name:    t.ConditionName,
			Context: conditionContextPtr(t.ConditionContext),
		},
	}
	deleteKey := fgaclient.ClientTupleKeyWithoutCondition{
		User:     t.User,
		Relation: t.Relation,
		Object:   t.Object,
	}

	_, err := f.client.Write(callCtx).Body(fgaclient.ClientWriteRequest{
		Writes:  []fgaclient.ClientTupleKey{writeKey},
		Deletes: []fgaclient.ClientTupleKeyWithoutCondition{deleteKey},
	}).Execute()

	durationMs := time.Since(start).Milliseconds()
	span.SetAttributes(attribute.Int64("authz.duration_ms", durationMs))

	if err != nil {
		// If the delete leg fails because the tuple doesn't yet exist, fall
		// back to a plain conditional write. This covers the pre-backfill
		// window where RevokeUserSessions runs before the backfill Job has
		// seeded the initial active_session tuple.
		if isTupleNotFoundError(err) {
			span.SetStatus(codes.Ok, "")
			f.logger.Debug("authz: UpdateConditionalTuple fallback to WriteConditional (no prior tuple)",
				"user", t.User, "relation", t.Relation, "object", t.Object,
				"condition", t.ConditionName, "duration_ms", durationMs,
			)
			return f.WriteConditional(ctx, t)
		}
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "UpdateConditionalTuple")
		return typedErr
	}

	span.SetStatus(codes.Ok, "")
	f.logger.Debug("authz: UpdateConditionalTuple",
		"user", t.User, "relation", t.Relation, "object", t.Object,
		"condition", t.ConditionName, "duration_ms", durationMs,
	)
	return nil
}

// conditionContextPtr makes a defensive copy of m and returns a pointer to the
// copy, as required by the OpenFGA SDK's RelationshipCondition.Context field
// (*map[string]any). Returns nil when m is nil or empty. The copy prevents the
// caller's map from being mutated if the SDK modifies the value after a write.
//
// The *map[string]any return type is dictated by the OpenFGA SDK — there is no
// way to avoid the pointer-to-map here. Suppress the gocritic ptrToRefParam
// diagnostic because the SDK signature forces this shape.
//
//nolint:gocritic // ptrToRefParam: *map required by fgasdk.RelationshipCondition.Context
func conditionContextPtr(m map[string]any) *map[string]any {
	if len(m) == 0 {
		return nil
	}
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return &cp
}

// extractID extracts the ID portion from an FGA object reference.
// e.g. "tenant:acme" → "acme", "system_tenant:_system" → "_system"
func extractID(objectRef string) string {
	for i := len(objectRef) - 1; i >= 0; i-- {
		if objectRef[i] == ':' {
			return objectRef[i+1:]
		}
	}
	return objectRef
}
