package authz

import (
	"context"
	"fmt"
	"time"

	fgasdk "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
func (f *fgaAuthorizer) ListUsers(ctx context.Context, objectType, object, relation string) ([]string, error) {
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

	f.logger.Debug("authz: ListUsers",
		"object_type", objectType,
		"object", object,
		"relation", relation,
		"result_count", len(userRefs),
		"duration_ms", durationMs,
	)

	return userRefs, nil
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
