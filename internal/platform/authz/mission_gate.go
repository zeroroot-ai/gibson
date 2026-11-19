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
)

// MissionGateWriter keeps the mission gate tuple (gibson#1389):
//
//	tenant:<id> | active | mission:<id>   condition mission_active{active: true}
//
// The gate is open while the tuple exists with active true. An absent tuple is
// closed, and ext-authz refuses the call (fail closed). So the gate is written
// to open it, and deleted to close it. It never holds a tuple with active
// false, and the write never makes the tuple absent while it is correct.
type MissionGateWriter interface {
	// SetMissionGate opens (active) or closes (not active) the gate of a mission.
	// Opening a gate that is already open sends no write. Closing a gate that is
	// already closed is not an error. When it returns nil after an open, the
	// tuple is confirmed: a check with higher consistency sees it.
	SetMissionGate(ctx context.Context, tenant, mission string, active bool) error
}

var _ MissionGateWriter = (*fgaAuthorizer)(nil)

// SetMissionGate implements MissionGateWriter.
//
// Open: read the gate with higher consistency. When it is open, stop. When it is
// closed, write the tuple in one request. The request fails when a tuple of an
// older shape already exists (active false, written by an older daemon). Then
// the gate was closed, so the delete and write of UpdateConditionalTuple leave
// no open gate absent.
//
// Close: delete the tuple in one request. A tuple that does not exist is benign.
func (f *fgaAuthorizer) SetMissionGate(ctx context.Context, tenant, mission string, active bool) error {
	if tenant == "" || mission == "" {
		return newInvalidArgumentError(fmt.Sprintf("SetMissionGate: tenant=%q mission=%q — both must be non-empty", tenant, mission))
	}
	tuple := MissionActiveTuple(tenant, mission, true)

	spanCtx, span := f.startSpan(ctx, spanWrite,
		attribute.String("authz.user", tuple.User),
		attribute.String("authz.object", tuple.Object),
		attribute.Bool("authz.mission_active", active),
		attribute.String("authz.op", "set_mission_gate"),
	)
	defer span.End()

	if !active {
		callCtx, cancel := f.callContext(spanCtx)
		defer cancel()
		_, err := f.client.Write(callCtx).Body(fgaclient.ClientWriteRequest{
			Deletes: []fgaclient.ClientTupleKeyWithoutCondition{{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}},
		}).Execute()
		if err != nil && !isTupleNotFoundError(err) {
			typedErr := mapSDKError(err)
			f.recordSpanError(span, typedErr, "SetMissionGate:close")
			return typedErr
		}
		return nil
	}

	open, err := f.checkHigherConsistency(spanCtx, tuple)
	if err != nil {
		f.recordSpanError(span, err, "SetMissionGate:read")
		return err
	}
	if open {
		return nil
	}
	callCtx, cancel := f.callContext(spanCtx)
	defer cancel()
	_, err = f.client.WriteTuples(callCtx).Body([]fgaclient.ClientTupleKey{{
		User: tuple.User, Relation: tuple.Relation, Object: tuple.Object,
		Condition: &fgasdk.RelationshipCondition{Name: tuple.ConditionName, Context: conditionContextPtr(tuple.ConditionContext)},
	}}).Execute()
	switch {
	case err == nil:
		return nil
	case isAlreadyExistsError(err):
		// A closed tuple of an older shape. The gate is closed now, so replacing
		// it opens it and leaves nothing open that is absent.
		return f.UpdateConditionalTuple(ctx, tuple)
	default:
		typedErr := mapSDKError(err)
		f.recordSpanError(span, typedErr, "SetMissionGate:open")
		return typedErr
	}
}

// checkHigherConsistency asks whether the tuple holds, and asks for higher
// consistency, so an answer from a cache older than a confirmed write is not
// accepted.
func (f *fgaAuthorizer) checkHigherConsistency(ctx context.Context, t ConditionalTuple) (bool, error) {
	callCtx, cancel := f.callContext(ctx)
	defer cancel()
	start := time.Now()
	pref := fgasdk.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY
	resp, err := f.client.Check(callCtx).Body(fgaclient.ClientCheckRequest{
		User: t.User, Relation: t.Relation, Object: t.Object,
	}).Options(fgaclient.ClientCheckOptions{Consistency: &pref}).Execute()
	if err != nil {
		return false, mapSDKError(err)
	}
	f.logger.Debug("authz: mission gate read", "object", t.Object, "open", resp.GetAllowed(),
		"duration_ms", time.Since(start).Milliseconds())
	return resp.GetAllowed(), nil
}

// ConsistentChecker is the optional interface of an Authorizer that answers a check
// with higher consistency. A check of a right that an admin can take away at once
// uses it, so an answer from a cache older than a confirmed delete is not accepted.
type ConsistentChecker interface {
	// CheckHigherConsistency reports whether the user holds the relation on the
	// object, with higher consistency.
	CheckHigherConsistency(ctx context.Context, user, relation, object string) (bool, error)
}

// CheckHigherConsistency implements ConsistentChecker.
func (f *fgaAuthorizer) CheckHigherConsistency(ctx context.Context, user, relation, object string) (bool, error) {
	return f.checkHigherConsistency(ctx, ConditionalTuple{User: user, Relation: relation, Object: object})
}
