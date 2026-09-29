// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/fgaevent"
)

// Tuple is one FGA relationship tuple, restated here so this package does
// not force every implementation to depend on internal/platform/authz (the
// tenant-operator's FGA client is a separate type).
type Tuple struct{ User, Relation, Object string }

// Tuples is the FGA side of a tenant role. Implementations must publish the
// FGA write event (gibson:fga.write) on WriteAndDelete so the ext-authz
// decision cache drops stale entries.
type Tuples interface {
	// ReadRoles returns the stored (direct) role tuples on tenant:<tenantID>
	// whose user is of type "user", for the four role relations
	// (Relations). When userIDs is non-empty, it returns only the tuples of
	// those users.
	ReadRoles(ctx context.Context, tenantID string, userIDs []string) ([]Tuple, error)
	// WriteAndDelete applies both lists in one FGA Write request.
	WriteAndDelete(ctx context.Context, writes, deletes []Tuple) error
}

// AuthzTuples adapts the daemon's authz.Authorizer. It needs
// authz.TupleReader and authz.AtomicWriter; it returns an error at
// construction when either is missing, so a Syncer is never built on top of
// an authorizer that cannot support it.
func AuthzTuples(a authz.Authorizer) (Tuples, error) {
	reader, ok := a.(authz.TupleReader)
	if !ok {
		return nil, fmt.Errorf("tenantrole: authorizer %T does not implement authz.TupleReader", a)
	}
	writer, ok := a.(authz.AtomicWriter)
	if !ok {
		return nil, fmt.Errorf("tenantrole: authorizer %T does not implement authz.AtomicWriter", a)
	}
	return &authzTuples{reader: reader, writer: writer}, nil
}

// AuthzTuplesPublishing is AuthzTuples with an FGA write event per tuple
// (fgaevent) so ext-authz drops the affected decisions at once (hosted#204).
func AuthzTuplesPublishing(a authz.Authorizer, pub fgaevent.Publisher) (Tuples, error) {
	t, err := AuthzTuples(a)
	if err != nil {
		return nil, err
	}
	t.(*authzTuples).pub = pub
	return t, nil
}

type authzTuples struct {
	reader authz.TupleReader
	writer authz.AtomicWriter
	pub    fgaevent.Publisher // nil: no event, the ext-authz cache TTL is the bound
}

func (t *authzTuples) ReadRoles(ctx context.Context, tenantID string, userIDs []string) ([]Tuple, error) {
	object := "tenant:" + tenantID
	stored, err := t.reader.ReadTuples(ctx, "", "", object)
	if err != nil {
		return nil, fmt.Errorf("tenantrole: ReadRoles tenant=%s: %w", tenantID, err)
	}

	roleRelation := make(map[string]bool, len(Relations))
	for _, r := range Relations {
		roleRelation[r] = true
	}
	var want map[string]bool
	if len(userIDs) > 0 {
		want = make(map[string]bool, len(userIDs))
		for _, id := range userIDs {
			want["user:"+id] = true
		}
	}

	out := make([]Tuple, 0, len(stored))
	for _, tup := range stored {
		if !roleRelation[tup.Relation] {
			continue
		}
		if !IsZitadelUserSubject(tup.User) {
			continue
		}
		if want != nil && !want[tup.User] {
			continue
		}
		out = append(out, Tuple{User: tup.User, Relation: tup.Relation, Object: tup.Object})
	}
	return out, nil
}

func (t *authzTuples) WriteAndDelete(ctx context.Context, writes, deletes []Tuple) error {
	if err := t.writer.WriteAndDelete(ctx, toAuthzTuples(writes), toAuthzTuples(deletes)); err != nil {
		return fmt.Errorf("tenantrole: WriteAndDelete: %w", err)
	}
	if t.pub != nil {
		for _, w := range writes {
			t.pub.Publish(ctx, fgaevent.FromTuple(fgaevent.OpWrite, w.User, w.Relation, w.Object))
		}
		for _, d := range deletes {
			t.pub.Publish(ctx, fgaevent.FromTuple(fgaevent.OpDelete, d.User, d.Relation, d.Object))
		}
	}
	return nil
}

func toAuthzTuples(in []Tuple) []authz.Tuple {
	if len(in) == 0 {
		return nil
	}
	out := make([]authz.Tuple, len(in))
	for i, t := range in {
		out[i] = authz.Tuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}
