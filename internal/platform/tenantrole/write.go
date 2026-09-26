// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import (
	"context"
	"errors"
	"fmt"
)

// Assign makes r the user's one role: it updates the user's existing active
// grant, or creates one when none exists, then calls Sync for that user so
// FGA matches at once.
func (s *Syncer) Assign(ctx context.Context, t Tenant, userID string, r Role) error {
	if t.ID == "" || t.OrgID == "" {
		return fmt.Errorf("tenantrole: Assign requires a tenant id and org id, got %+v", t)
	}
	if userID == "" {
		return errors.New("tenantrole: Assign requires a userID")
	}
	existing, err := s.activeGrant(ctx, t, userID)
	if err != nil {
		return fmt.Errorf("tenantrole: Assign tenant=%s user=%s: %w", t.ID, userID, err)
	}
	if existing != nil {
		if err := s.grants.Update(ctx, existing.ID, r); err != nil {
			return fmt.Errorf("tenantrole: Assign tenant=%s user=%s: update grant: %w", t.ID, userID, err)
		}
	} else {
		if _, err := s.grants.Create(ctx, t.OrgID, userID, r); err != nil {
			return fmt.Errorf("tenantrole: Assign tenant=%s user=%s: create grant: %w", t.ID, userID, err)
		}
	}
	if _, err := s.Sync(ctx, t, userID); err != nil {
		return fmt.Errorf("tenantrole: Assign tenant=%s user=%s: %w", t.ID, userID, err)
	}
	return nil
}

// Revoke deletes the user's active grant, then calls Sync for that user.
func (s *Syncer) Revoke(ctx context.Context, t Tenant, userID string) error {
	if t.ID == "" || t.OrgID == "" {
		return fmt.Errorf("tenantrole: Revoke requires a tenant id and org id, got %+v", t)
	}
	if userID == "" {
		return errors.New("tenantrole: Revoke requires a userID")
	}
	grants, err := s.grants.List(ctx, t.OrgID, []string{userID})
	if err != nil {
		return fmt.Errorf("tenantrole: Revoke tenant=%s user=%s: list grants: %w", t.ID, userID, err)
	}
	for _, g := range grants {
		if g.UserID != userID || !g.Active {
			continue
		}
		if err := s.grants.Delete(ctx, g.ID); err != nil {
			return fmt.Errorf("tenantrole: Revoke tenant=%s user=%s: delete grant: %w", t.ID, userID, err)
		}
	}
	if _, err := s.Sync(ctx, t, userID); err != nil {
		return fmt.Errorf("tenantrole: Revoke tenant=%s user=%s: %w", t.ID, userID, err)
	}
	return nil
}

// Transfer makes `to` the Owner and `from` an Admin in Zitadel (two
// UpdateAuthorization-shaped calls, `to` first), then calls Sync(from, to),
// which moves both in one FGA transaction. Owner rules (who may call this)
// stay in the RPC handler.
//
// Zitadel has no transaction across two grants: if this stops between the
// two Zitadel writes, Zitadel briefly holds two Owners. Sync then returns
// ErrOwnerConflict and leaves FGA on the old Owner; a retry of the same
// call completes the transfer.
func (s *Syncer) Transfer(ctx context.Context, t Tenant, from, to string) error {
	if t.ID == "" || t.OrgID == "" {
		return fmt.Errorf("tenantrole: Transfer requires a tenant id and org id, got %+v", t)
	}
	if from == "" || to == "" || from == to {
		return fmt.Errorf("tenantrole: Transfer requires two distinct users, got from=%q to=%q", from, to)
	}
	fromGrant, err := s.activeGrant(ctx, t, from)
	if err != nil {
		return fmt.Errorf("tenantrole: Transfer tenant=%s: %w", t.ID, err)
	}
	toGrant, err := s.activeGrant(ctx, t, to)
	if err != nil {
		return fmt.Errorf("tenantrole: Transfer tenant=%s: %w", t.ID, err)
	}

	if toGrant != nil {
		if err := s.grants.Update(ctx, toGrant.ID, Owner); err != nil {
			return fmt.Errorf("tenantrole: Transfer tenant=%s: promote %s: %w", t.ID, to, err)
		}
	} else if _, err := s.grants.Create(ctx, t.OrgID, to, Owner); err != nil {
		return fmt.Errorf("tenantrole: Transfer tenant=%s: promote %s: %w", t.ID, to, err)
	}

	if fromGrant != nil {
		if err := s.grants.Update(ctx, fromGrant.ID, Admin); err != nil {
			return fmt.Errorf("tenantrole: Transfer tenant=%s: demote %s: %w", t.ID, from, err)
		}
	} else if _, err := s.grants.Create(ctx, t.OrgID, from, Admin); err != nil {
		return fmt.Errorf("tenantrole: Transfer tenant=%s: demote %s: %w", t.ID, from, err)
	}

	if _, err := s.Sync(ctx, t, from, to); err != nil {
		return fmt.Errorf("tenantrole: Transfer tenant=%s: %w", t.ID, err)
	}
	return nil
}

// activeGrant returns the user's one active grant on the tenant's project,
// or nil when none exists.
func (s *Syncer) activeGrant(ctx context.Context, t Tenant, userID string) (*Grant, error) {
	grants, err := s.grants.List(ctx, t.OrgID, []string{userID})
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	for i := range grants {
		if grants[i].UserID == userID && grants[i].Active {
			return &grants[i], nil
		}
	}
	return nil, nil
}
