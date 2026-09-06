// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"fmt"
	"time"

	fgaclient "github.com/openfga/go-sdk/client"
	"go.opentelemetry.io/otel/attribute"
)

// spanReadTuples is the OTel span name for a ReadTuples call.
const spanReadTuples = "gibson.authz.fga_read_tuples"

// readTuplesPageSize is the page size used when walking the Read cursor.
const readTuplesPageSize = int32(100)

// readTuplesMaxPages bounds the walk. A migration that needs more than this
// many pages of one filter is not a migration, it is a mistake, and looping
// forever against a paginating server is worse than stopping loudly.
const readTuplesMaxPages = 1000

// TupleReader is the optional interface for reading STORED relationship tuples
// back out of FGA, as opposed to evaluating them.
//
// It is deliberately not on Authorizer. Authorizer is the authorization
// contract — the questions an allow/deny decision asks — and every one of its
// listing methods answers an EFFECTIVE question: ListUsers("team", t, "admin")
// includes users who are admin only because `admin: [user] or admin from
// parent` derives it from the tenant. That is the right answer for a decision
// and the wrong one for a rewrite: materialising derived users as direct tuples
// would turn "is currently a tenant admin" into "is permanently a team admin".
//
// ReadTuples answers the other question — which tuples are actually stored —
// which is the only safe basis for moving them. It follows the ConditionalWriter
// precedent: callers that need it type-assert the Authorizer they hold, so the
// base interface and every test double stay untouched.
type TupleReader interface {
	// ReadTuples returns the stored tuples matching the filter. Empty fields
	// are wildcards, with OpenFGA's own constraint: object may be a full
	// reference ("team:acme/ops") or a bare type filter ("team:"), and when
	// object is empty both user and relation must be set.
	//
	// The returned tuples are exactly as stored — no derivation, no expansion.
	ReadTuples(ctx context.Context, user, relation, object string) ([]Tuple, error)
}

// ReadTuples implements TupleReader against OpenFGA's Read API.
func (f *fgaAuthorizer) ReadTuples(ctx context.Context, user, relation, object string) ([]Tuple, error) {
	if object == "" && (user == "" || relation == "") {
		return nil, newInvalidArgumentError(
			fmt.Sprintf("ReadTuples: user=%q relation=%q object=%q — with no object filter, both user and relation are required",
				user, relation, object),
		)
	}

	start := time.Now()
	spanCtx, span := f.startSpan(ctx, spanReadTuples,
		attribute.String("authz.user", user),
		attribute.String("authz.relation", relation),
		attribute.String("authz.object", object),
	)
	defer span.End()

	body := fgaclient.ClientReadRequest{}
	if user != "" {
		body.User = &user
	}
	if relation != "" {
		body.Relation = &relation
	}
	if object != "" {
		body.Object = &object
	}

	var (
		out               []Tuple
		continuationToken string
	)
	for page := 0; ; page++ {
		if page >= readTuplesMaxPages {
			return nil, fmt.Errorf("authz: ReadTuples exceeded %d pages for user=%q relation=%q object=%q",
				readTuplesMaxPages, user, relation, object)
		}

		opts := fgaclient.ClientReadOptions{PageSize: ptrTo(readTuplesPageSize)}
		if continuationToken != "" {
			opts.ContinuationToken = ptrTo(continuationToken)
		}

		callCtx, cancel := f.callContext(spanCtx)
		resp, err := f.client.Read(callCtx).Body(body).Options(opts).Execute()
		cancel()
		if err != nil {
			typedErr := mapSDKError(err)
			f.recordSpanError(span, typedErr, "ReadTuples")
			return nil, typedErr
		}

		for _, t := range resp.GetTuples() {
			key := t.GetKey()
			out = append(out, Tuple{
				User:     key.GetUser(),
				Relation: key.GetRelation(),
				Object:   key.GetObject(),
			})
		}

		continuationToken = resp.GetContinuationToken()
		if continuationToken == "" {
			break
		}
	}

	span.SetAttributes(
		attribute.Int("authz.result_count", len(out)),
		attribute.Int64("authz.duration_ms", time.Since(start).Milliseconds()),
	)
	f.logger.Debug("authz: ReadTuples",
		"user", user,
		"relation", relation,
		"object", object,
		"result_count", len(out),
	)
	return out, nil
}

func ptrTo[T any](v T) *T { return &v }
