// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — produced_component.go implements the daemon side of
// ComponentService.EnrollComponent (gibson#33).
//
// An agent that produced a tool, an agent or a plugin enrolls it. The
// enrollment is autonomous but bounded by policy (the decision of the
// 2026-08-02 grill, option C):
//
//   - Tenant-scoped. The tenant and the producer come from the verified
//     identity of the caller. The request names neither.
//   - The producer is an agent of the tenant. A tool or a plugin cannot
//     enroll a component.
//   - The person who owns the producer owns the new component. A producer
//     with no owner cannot enroll.
//   - The platform assigns the trust (gibson#554, ADR-0097). A produced
//     component never takes a catalog name, so it is never trusted.
//   - A quota for each tenant bounds the count. A quota read that fails
//     refuses the enrollment.
//   - The bootstrap token is short-lived, for the new component only, and
//     carries no session capability.
//   - Each enrollment writes a durable audit record before any grant.
package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
)

const (
	// ProducedComponentLimitEnv sets how many components agents may enroll
	// in one tenant.
	ProducedComponentLimitEnv = "GIBSON_PRODUCED_COMPONENT_LIMIT"

	// DefaultProducedComponentLimit is the quota when the variable is empty.
	DefaultProducedComponentLimit = 25

	// producedComponentTokenTTL is the life of the bootstrap token of a
	// produced component. The component starts at once after the build, so
	// a short life is enough.
	producedComponentTokenTTL = 15 * time.Minute
)

// ProducedComponentLimitFromEnv reads the quota. An empty variable gives the
// default. A value that is not a positive number is an error, so the daemon
// does not start with a quota that no one chose.
func ProducedComponentLimitFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv(ProducedComponentLimitEnv))
	if raw == "" {
		return DefaultProducedComponentLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s=%q is not a positive number", ProducedComponentLimitEnv, raw)
	}
	return n, nil
}

// ProducedComponent is a component that an agent produced.
type ProducedComponent struct {
	Kind        string // agent, tool or plugin
	Name        string
	Version     string
	Image       string // OCI reference, pinned by digest
	Description string
}

// EnrolledComponent is the identity and the credential of a produced
// component.
type EnrolledComponent struct {
	PrincipalID    string
	BootstrapToken string
	ExpiresAt      time.Time
}

// errProducedQuota reports a tenant whose agents enrolled the quota.
var errProducedQuota = errors.New("the tenant reached its quota of components that agents enroll")

// errProducedExists reports a name that a produced component of the same
// kind already holds in the tenant.
var errProducedExists = errors.New("a produced component with this kind and name exists")

// producedComponentStore holds one row for each enrollment. Reserve takes the
// quota and the name under a lock on the tenant. Bind records the identity.
// Release removes a reservation whose identity was not created.
type producedComponentStore interface {
	Reserve(ctx context.Context, tenantID, ownerUserID, producer string, c ProducedComponent, limit int) error
	Bind(ctx context.Context, tenantID, kind, name, principalID string) error
	Release(ctx context.Context, tenantID, kind, name string) error
}

// sqlProducedComponentStore is the producedComponentStore on the platform
// Postgres (migration 042).
type sqlProducedComponentStore struct{ db *sql.DB }

func (st sqlProducedComponentStore) Reserve(ctx context.Context, tenantID, ownerUserID, producer string, c ProducedComponent, limit int) (err error) {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("produced component: begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('produced_component:' || $1))`, tenantID); err != nil {
		return fmt.Errorf("produced component: lock tenant %q: %w", tenantID, err)
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM produced_component WHERE tenant_id = $1`, tenantID).Scan(&count); err != nil {
		return fmt.Errorf("produced component: count tenant %q: %w", tenantID, err)
	}
	if count >= limit {
		err = errProducedQuota
		return err
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO produced_component (tenant_id, kind, name, version, image, producer_principal, owner_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, kind, name) DO NOTHING`,
		tenantID, c.Kind, c.Name, c.Version, c.Image, producer, ownerUserID)
	if err != nil {
		return fmt.Errorf("produced component: reserve %s/%s: %w", c.Kind, c.Name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("produced component: reserve %s/%s: %w", c.Kind, c.Name, err)
	}
	if n == 0 {
		err = errProducedExists
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("produced component: commit: %w", err)
	}
	return nil
}

func (st sqlProducedComponentStore) Bind(ctx context.Context, tenantID, kind, name, principalID string) error {
	if _, err := st.db.ExecContext(ctx,
		`UPDATE produced_component SET principal_id = $4 WHERE tenant_id = $1 AND kind = $2 AND name = $3`,
		tenantID, kind, name, principalID); err != nil {
		return fmt.Errorf("produced component: bind %s/%s: %w", kind, name, err)
	}
	return nil
}

func (st sqlProducedComponentStore) Release(ctx context.Context, tenantID, kind, name string) error {
	if _, err := st.db.ExecContext(ctx,
		`DELETE FROM produced_component WHERE tenant_id = $1 AND kind = $2 AND name = $3 AND principal_id = ''`,
		tenantID, kind, name); err != nil {
		return fmt.Errorf("produced component: release %s/%s: %w", kind, name, err)
	}
	return nil
}

// WithProducedComponents wires the record of produced components on the
// platform database, and the quota for each tenant.
func (s *DaemonServer) WithProducedComponents(db *sql.DB, limit int) *DaemonServer {
	if db != nil {
		s.producedComponents = sqlProducedComponentStore{db: db}
	}
	s.producedComponentLimit = limit
	return s
}

// producedKind maps a component kind to its IdP role and FGA type.
func producedKind(kind string) (idp.Role, string, error) {
	switch kind {
	case "agent":
		return idp.RoleAgent, "agent_principal", nil
	case "tool":
		return idp.RoleTool, "tool_principal", nil
	case "plugin":
		return idp.RolePlugin, "plugin_principal", nil
	default:
		return "", "", fmt.Errorf("kind must be agent, tool or plugin, got %q", kind)
	}
}

// EnrollProducedComponent enrolls a component that the agent producer
// produced, in the tenant tenantID. tenantID and producer come from the
// verified identity of the caller. It returns gRPC status errors.
func (s *DaemonServer) EnrollProducedComponent(ctx context.Context, tenantID, producer string, c ProducedComponent) (EnrolledComponent, error) {
	if tenantID == "" || producer == "" {
		return EnrolledComponent{}, status_grpc.Error(codes.PermissionDenied, "no tenant or no component identity in context")
	}
	if !strings.HasPrefix(producer, "agent_principal:") {
		return EnrolledComponent{}, status_grpc.Error(codes.PermissionDenied, "only an agent enrolls a component that it produced")
	}
	role, fgaType, err := producedKind(c.Kind)
	if err != nil {
		return EnrolledComponent{}, status_grpc.Error(codes.InvalidArgument, err.Error())
	}
	if !nameRegex.MatchString(c.Name) {
		return EnrolledComponent{}, status_grpc.Errorf(codes.InvalidArgument,
			"name %q is invalid: must match ^[a-z][a-z0-9-]{2,40}$", c.Name)
	}
	if c.Version == "" {
		return EnrolledComponent{}, status_grpc.Error(codes.InvalidArgument, "version is required")
	}
	if !strings.Contains(c.Image, "@sha256:") {
		return EnrolledComponent{}, status_grpc.Error(codes.InvalidArgument, "image must be pinned by digest")
	}
	// The platform assigns the trust: a catalog name is the platform's. A
	// produced component under that name would take the trust of the
	// catalog entry (gibson#554).
	if _, listed := componentcatalog.LookupContentTrust(c.Kind, c.Name); listed {
		return EnrolledComponent{}, status_grpc.Errorf(codes.PermissionDenied,
			"the name %q belongs to a platform component, use another name", c.Name)
	}
	if s.authorizer == nil {
		return EnrolledComponent{}, status_grpc.Error(codes.Unavailable, "authorization not configured")
	}
	if s.producedComponents == nil || s.producedComponentLimit < 1 {
		// Fail closed: with no quota store, no enrollment is bounded.
		return EnrolledComponent{}, status_grpc.Error(codes.Unavailable, "the quota of produced components is not configured")
	}

	// The producer must be an identity of this tenant.
	inTenant, err := s.authorizer.Check(ctx, "tenant:"+tenantID, "belongs_to", producer)
	if err != nil {
		return EnrolledComponent{}, status_grpc.Errorf(codes.Internal, "check the producer: %v", err)
	}
	if !inTenant {
		return EnrolledComponent{}, status_grpc.Error(codes.PermissionDenied, "the producer is not an identity of this tenant")
	}
	owner, err := s.identityOwner(ctx, "agent_principal", producer)
	if err != nil {
		return EnrolledComponent{}, status_grpc.Errorf(codes.Internal, "find the owner of the producer: %v", err)
	}
	if owner == "" {
		return EnrolledComponent{}, status_grpc.Error(codes.FailedPrecondition,
			"the producer has no owner, so no person is accountable for what it enrolls")
	}

	switch err := s.producedComponents.Reserve(ctx, tenantID, owner, producer, c, s.producedComponentLimit); {
	case errors.Is(err, errProducedQuota):
		return EnrolledComponent{}, status_grpc.Errorf(codes.ResourceExhausted,
			"the tenant reached its quota of %d components that agents enroll", s.producedComponentLimit)
	case errors.Is(err, errProducedExists):
		return EnrolledComponent{}, status_grpc.Errorf(codes.AlreadyExists,
			"a produced %s named %q exists in this tenant", c.Kind, c.Name)
	case err != nil:
		return EnrolledComponent{}, status_grpc.Errorf(codes.Unavailable, "the quota could not be read: %v", err)
	}

	description := strings.TrimSpace(c.Description)
	if description == "" {
		description = "produced by " + producer
	}
	provisioned, err := s.provisionIdentity(ctx, identitySpec{
		TenantID:    tenantID,
		OwnerUserID: owner,
		ActorID:     producer,
		ActorType:   "agent",
		AuditAction: "component.enrolled_by_agent",
		Role:        role,
		FGAType:     fgaType,
		Name:        c.Name,
		Description: description,
		TokenTTL:    producedComponentTokenTTL,
	})
	if err != nil {
		if relErr := s.producedComponents.Release(ctx, tenantID, c.Kind, c.Name); relErr != nil {
			s.logger.ErrorContext(ctx, "EnrollComponent: release of the reservation failed",
				slog.String("tenant_id", tenantID), slog.String("name", c.Name), slog.String("error", relErr.Error()))
		}
		return EnrolledComponent{}, err
	}
	if err := s.producedComponents.Bind(ctx, tenantID, c.Kind, c.Name, provisioned.PrincipalID); err != nil {
		// The identity exists and the reservation holds the quota. Only the
		// link is missing, so the enrollment stands.
		s.logger.ErrorContext(ctx, "EnrollComponent: the record of the produced component has no principal",
			slog.String("tenant_id", tenantID), slog.String("principal_id", provisioned.PrincipalID), slog.String("error", err.Error()))
	}
	s.logger.InfoContext(ctx, "produced component enrolled",
		slog.String("tenant_id", tenantID),
		slog.String("producer", producer),
		slog.String("principal_id", provisioned.PrincipalID),
		slog.String("kind", c.Kind),
		slog.String("name", c.Name),
		slog.String("image", c.Image),
	)
	return EnrolledComponent{
		PrincipalID:    provisioned.PrincipalID,
		BootstrapToken: provisioned.BootstrapToken,
		ExpiresAt:      time.Now().UTC().Add(producedComponentTokenTTL),
	}, nil
}
