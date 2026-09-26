// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
)

// TenantRoleTuples adapts this package's Client to tenantrole.Tuples, so the
// tenant-operator's drift-repair timer (ADR-0093 decision 3) can build a
// tenantrole.Syncer over the same fga.Client every other operator write
// already goes through — including the WithEventPublisher wrapper, so a
// Sync's WriteAndDelete still invalidates the ext-authz decision cache.
type TenantRoleTuples struct {
	client Client
}

// NewTenantRoleTuples wraps client. client must be non-nil.
func NewTenantRoleTuples(client Client) *TenantRoleTuples {
	return &TenantRoleTuples{client: client}
}

// ReadRoles implements tenantrole.Tuples.
func (t *TenantRoleTuples) ReadRoles(ctx context.Context, tenantID string, userIDs []string) ([]tenantrole.Tuple, error) {
	object := "tenant:" + tenantID
	stored, err := t.client.Read(ctx, Tuple{Object: object})
	if err != nil {
		return nil, fmt.Errorf("tenantrole: ReadRoles tenant=%s: %w", tenantID, err)
	}

	roleRelation := make(map[string]bool, len(tenantrole.Relations))
	for _, r := range tenantrole.Relations {
		roleRelation[r] = true
	}
	var want map[string]bool
	if len(userIDs) > 0 {
		want = make(map[string]bool, len(userIDs))
		for _, id := range userIDs {
			want["user:"+id] = true
		}
	}

	out := make([]tenantrole.Tuple, 0, len(stored))
	for _, tup := range stored {
		if !roleRelation[tup.Relation] {
			continue
		}
		if !tenantrole.IsZitadelUserSubject(tup.User) {
			continue
		}
		if want != nil && !want[tup.User] {
			continue
		}
		out = append(out, tenantrole.Tuple{User: tup.User, Relation: tup.Relation, Object: tup.Object})
	}
	return out, nil
}

// WriteAndDelete implements tenantrole.Tuples.
func (t *TenantRoleTuples) WriteAndDelete(ctx context.Context, writes, deletes []tenantrole.Tuple) error {
	if err := t.client.WriteAndDelete(ctx, toFGATuples(writes), toFGATuples(deletes)); err != nil {
		return fmt.Errorf("tenantrole: WriteAndDelete: %w", err)
	}
	return nil
}

func toFGATuples(in []tenantrole.Tuple) []Tuple {
	if len(in) == 0 {
		return nil
	}
	out := make([]Tuple, len(in))
	for i, t := range in {
		out[i] = Tuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}
