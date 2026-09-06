// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Store is the daemon's single source of truth for banks and their members.
// Every method is tenant-scoped: the tenant selects the database, so one
// tenant's bank id can never resolve in another tenant.
type Store interface {
	// Create stores a new bank. It returns ErrAlreadyExists when the name is
	// taken and ErrInvalid when the input could never describe a running bank.
	Create(ctx context.Context, tenantID string, in CreateInput) (*Bank, error)

	// Get returns one bank by id, or ErrNotFound.
	Get(ctx context.Context, tenantID, id string) (*Bank, error)

	// List returns one page of the tenant's banks, newest first.
	List(ctx context.Context, tenantID string, page Page) ([]*Bank, string, error)

	// Update changes the fields an owner may change. Absent fields keep their
	// value. It returns ErrNotFound when no bank has that id.
	Update(ctx context.Context, tenantID, id string, in UpdateInput) (*Bank, error)

	// Delete removes a bank and its member rows. It returns ErrNotFound when
	// no bank has that id. Draining the running members is the reconciler's
	// job; this removes the record the reconciler works from.
	Delete(ctx context.Context, tenantID, id string) error

	// ListMembers returns one page of a bank's members, oldest first, so a
	// reader sees them in the order they were launched.
	ListMembers(ctx context.Context, tenantID, bankID string, page Page) ([]*Member, string, error)

	// GetMember returns one member by id. ErrNotFound when there is none.
	GetMember(ctx context.Context, tenantID, memberID string) (*Member, error)

	// MemberByRun returns the member backed by a mission run, and the bank it
	// belongs to.
	//
	// It is how a member callback learns WHICH member is calling. The identity
	// on the request is the grant's, and the grant names the run; a member id
	// in the request body would let one member act as another. ErrNotFound
	// means the run is not a member's.
	MemberByRun(ctx context.Context, tenantID, missionRunID string) (*Member, error)

	// ListAll returns every bank of the tenant, unpaged. The reconciler needs
	// the whole set on every pass — a page would make it reconcile part of a
	// tenant and call it done — and a tenant holds tens of banks, not
	// thousands.
	ListAll(ctx context.Context, tenantID string) ([]*Bank, error)

	// AddMember records a member the reconciler launched.
	AddMember(ctx context.Context, tenantID string, m *Member) error

	// UpdateMemberStatus records what a member last reported. It sets
	// last_heartbeat, so a member that stops reporting can be found.
	UpdateMemberStatus(ctx context.Context, tenantID, memberID string, status MemberStatus) (*Member, error)

	// SetMemberState moves a member the daemon, not the member, decides about:
	// LAUNCHING at birth, DRAINING on scale-down, DEAD when heartbeats stop.
	SetMemberState(ctx context.Context, tenantID, memberID string, state MemberState) (*Member, error)

	// RemoveMember deletes a member row after its sandbox is gone.
	RemoveMember(ctx context.Context, tenantID, memberID string) error
}

// MemberStatus is what a member reports on every heartbeat.
type MemberStatus struct {
	State         MemberState
	JobsInFlight  int32
	JobCap        int32
	ActiveJobIDs  []string
	ClaudeVersion string
}

// Validate checks that in could describe a bank that actually runs, and fills
// the defaults. It is called by Create, and exported so a handler can refuse a
// bad request with InvalidArgument before it reaches the database.
//
// The rules are the ones a running member depends on:
//   - a name, because names are how people address a bank;
//   - a known login shape, because the launch resolver switches on it;
//   - a person as owner for the subscription shape, because a subscription
//     belongs to a person and there is nobody to sign in otherwise;
//   - a provider configuration for every other shape, because the launch
//     resolves the credential from it and a member with no credential cannot
//     reach a model;
//   - a desired count and a job cap that are not negative.
func (in *CreateInput) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if in.OwnerKind != OwnerUser && in.OwnerKind != OwnerTenant {
		return fmt.Errorf("%w: owner kind %q must be %q or %q", ErrInvalid, in.OwnerKind, OwnerUser, OwnerTenant)
	}
	if strings.TrimSpace(in.OwnerID) == "" {
		return fmt.Errorf("%w: owner id is required", ErrInvalid)
	}
	if !IsLoginShape(in.LoginShape) {
		return fmt.Errorf("%w: login shape %q is not one of %s", ErrInvalid, in.LoginShape, strings.Join(LoginShapeNames(), ", "))
	}
	if in.LoginShape == LoginShapeSubscription && in.OwnerKind != OwnerUser {
		return fmt.Errorf("%w: the %s login shape needs a person as owner, because the sign in happens inside the sandbox and the subscription is theirs",
			ErrInvalid, LoginShapeSubscription)
	}
	if NeedsProviderConfig(in.LoginShape) && strings.TrimSpace(in.ProviderConfigName) == "" {
		return fmt.Errorf("%w: the %s login shape needs provider_config_name, or a member has no credential to reach a model with",
			ErrInvalid, in.LoginShape)
	}
	if in.LoginShape == LoginShapeSubscription && strings.TrimSpace(in.ProviderConfigName) != "" {
		return fmt.Errorf("%w: the %s login shape stores no credential, so it must not name a provider configuration",
			ErrInvalid, LoginShapeSubscription)
	}
	if in.DesiredCount < 0 {
		return fmt.Errorf("%w: desired count %d must not be negative", ErrInvalid, in.DesiredCount)
	}
	if in.MaxJobsInFlight < 0 {
		return fmt.Errorf("%w: max jobs in flight %d must not be negative", ErrInvalid, in.MaxJobsInFlight)
	}
	if in.StaleLimit < 0 {
		return fmt.Errorf("%w: stale limit %s must not be negative", ErrInvalid, in.StaleLimit)
	}
	if in.SpillPolicy == "" {
		in.SpillPolicy = SpillQueue
	}
	if !IsSpillPolicy(in.SpillPolicy) {
		return fmt.Errorf("%w: spill policy %q must be %q or %q", ErrInvalid, in.SpillPolicy, SpillQueue, SpillEphemeral)
	}
	if in.AgentName == "" {
		in.AgentName = DefaultAgentName
	}
	if in.MaxJobsInFlight == 0 {
		in.MaxJobsInFlight = DefaultMaxJobsInFlight
	}
	if in.StaleLimit == 0 {
		in.StaleLimit = DefaultStaleLimit
	}
	return nil
}

// Validate checks an update. It refuses a negative value rather than clamping
// it, so a caller learns what it asked for was wrong.
func (in *UpdateInput) Validate() error {
	if in.DesiredCount != nil && *in.DesiredCount < 0 {
		return fmt.Errorf("%w: desired count %d must not be negative", ErrInvalid, *in.DesiredCount)
	}
	if in.MaxJobsInFlight != nil && *in.MaxJobsInFlight < 0 {
		return fmt.Errorf("%w: max jobs in flight %d must not be negative", ErrInvalid, *in.MaxJobsInFlight)
	}
	if in.StaleLimit != nil && *in.StaleLimit < 0 {
		return fmt.Errorf("%w: stale limit %s must not be negative", ErrInvalid, *in.StaleLimit)
	}
	if in.SpillPolicy != nil && !IsSpillPolicy(*in.SpillPolicy) {
		return fmt.Errorf("%w: spill policy %q must be %q or %q", ErrInvalid, *in.SpillPolicy, SpillQueue, SpillEphemeral)
	}
	return nil
}

// LoginShapeNames returns every login shape, for an error that tells a caller
// what the valid values are.
func LoginShapeNames() []string {
	return []string{
		string(LoginShapeSubscription),
		string(LoginShapeAPIKey),
		string(LoginShapeBedrock),
		string(LoginShapeVertex),
		string(LoginShapeFoundry),
	}
}

// clampPageSize bounds a requested page size. Zero takes the default and a
// request above the maximum is capped rather than refused: a caller asking for
// too much gets a page, not an error.
func clampPageSize(size int32) int32 {
	switch {
	case size <= 0:
		return DefaultPageSize
	case size > MaxPageSize:
		return MaxPageSize
	default:
		return size
	}
}

// staleLimitSeconds converts a duration to the whole seconds the column holds.
func staleLimitSeconds(d time.Duration) int64 {
	return int64(d / time.Second)
}
