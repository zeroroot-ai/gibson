// Package provisioner — grant_handler.go
//
// GrantHandler manages per-user component access grants, backed by FGA tuples.
// Each grant allows a specific user to perform a specific action (execute,
// configure, or read) on a specific component.
//
// The three valid action strings map to FGA relations:
//
//	"execute"   → can_execute
//	"configure" → can_configure
//	"read"      → can_read
//
// All mutations emit a structured audit log entry (see logAuditEntry).
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrInvalidAction is returned when the action is not one of execute/configure/read.
	ErrInvalidAction = errors.New("grant: action must be one of execute, configure, read")

	// ErrGrantFailed is returned when the underlying FGA operation fails.
	ErrGrantFailed = errors.New("grant: operation failed")
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ComponentGrant describes a single component access grant held by a user.
type ComponentGrant struct {
	ComponentRef string // e.g. "tool:nuclei", "agent:opencode"
	Action       string // "execute", "configure", or "read"
}

// ---------------------------------------------------------------------------
// GrantHandler
// ---------------------------------------------------------------------------

// GrantHandler manages per-user component grants via FGA tuples.
// It is safe for concurrent use.
type GrantHandler struct {
	authz  authz.Authorizer
	logger *slog.Logger
}

// NewGrantHandler constructs a GrantHandler.
func NewGrantHandler(az authz.Authorizer, logger *slog.Logger) (*GrantHandler, error) {
	if az == nil {
		return nil, fmt.Errorf("grant_handler: Authorizer is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &GrantHandler{
		authz:  az,
		logger: logger.With("component", "provisioner.grant_handler"),
	}, nil
}

// Grant writes an FGA can_<action> tuple for the user on the component.
// Returns ErrInvalidAction when action is not one of execute/configure/read.
func (h *GrantHandler) Grant(ctx context.Context, tenantID, userID, componentRef, action string) error {
	relation, err := actionToRelation(action)
	if err != nil {
		return err
	}
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: relation,
		Object:   fmt.Sprintf("component:%s", normalizeRef(componentRef)),
	}
	if writeErr := h.authz.Write(ctx, []authz.Tuple{tuple}); writeErr != nil {
		return fmt.Errorf("%w: write FGA tuple for %s on %s: %v", ErrGrantFailed, action, componentRef, writeErr)
	}
	h.logger.InfoContext(ctx, "component grant added",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", userID),
		slog.String("component_ref", componentRef),
		slog.String("action", action),
		slog.String("event_type", "component_grant_added"),
	)
	return nil
}

// Revoke deletes the FGA can_<action> tuple for the user on the component.
// Returns ErrInvalidAction when action is not one of execute/configure/read.
func (h *GrantHandler) Revoke(ctx context.Context, tenantID, userID, componentRef, action string) error {
	relation, err := actionToRelation(action)
	if err != nil {
		return err
	}
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: relation,
		Object:   fmt.Sprintf("component:%s", normalizeRef(componentRef)),
	}
	if delErr := h.authz.Delete(ctx, []authz.Tuple{tuple}); delErr != nil {
		return fmt.Errorf("%w: delete FGA tuple for %s on %s: %v", ErrGrantFailed, action, componentRef, delErr)
	}
	h.logger.InfoContext(ctx, "component grant revoked",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", userID),
		slog.String("component_ref", componentRef),
		slog.String("action", action),
		slog.String("event_type", "component_grant_revoked"),
	)
	return nil
}

// List returns all component grants held by a user.
// It queries FGA for can_execute, can_configure, and can_read on all component objects.
func (h *GrantHandler) List(ctx context.Context, tenantID, userID string) ([]ComponentGrant, error) {
	user := fmt.Sprintf("user:%s", userID)
	var grants []ComponentGrant

	for _, action := range []string{"execute", "configure", "read"} {
		relation, _ := actionToRelation(action)
		objects, err := h.authz.ListObjects(ctx, user, relation, "component")
		if err != nil {
			return nil, fmt.Errorf("grant list: FGA ListObjects for %s: %w", action, err)
		}
		for _, obj := range objects {
			// obj is "component:<name>", strip the prefix.
			ref := strings.TrimPrefix(obj, "component:")
			grants = append(grants, ComponentGrant{
				ComponentRef: ref,
				Action:       action,
			})
		}
	}
	return grants, nil
}

// ---------------------------------------------------------------------------
// Batch operation
// ---------------------------------------------------------------------------

// BatchGrant applies a list of grant/revoke operations for the given user.
// It authorizes the caller once (done by the gRPC handler before calling this)
// and processes each change individually. Per-change errors are collected and
// returned alongside the success counts; a failure on one change does NOT
// abort the batch.
//
// Each change emits a structured audit log entry on success.
func (h *GrantHandler) BatchGrant(ctx context.Context, tenantID, userID string, changes []BatchChange) (granted, revoked int, errs []string) {
	for _, c := range changes {
		switch c.Operation {
		case "grant":
			if err := h.Grant(ctx, tenantID, userID, c.ComponentRef, c.Action); err != nil {
				errs = append(errs, fmt.Sprintf("grant %s %s: %v", c.ComponentRef, c.Action, err))
			} else {
				granted++
			}
		case "revoke":
			if err := h.Revoke(ctx, tenantID, userID, c.ComponentRef, c.Action); err != nil {
				errs = append(errs, fmt.Sprintf("revoke %s %s: %v", c.ComponentRef, c.Action, err))
			} else {
				revoked++
			}
		default:
			errs = append(errs, fmt.Sprintf("unknown operation %q for %s %s", c.Operation, c.ComponentRef, c.Action))
		}
	}
	return granted, revoked, errs
}

// BatchChange describes a single grant or revoke operation in a batch.
type BatchChange struct {
	ComponentRef string // e.g. "tool:nuclei"
	Action       string // "execute", "configure", or "read"
	Operation    string // "grant" or "revoke"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// actionToRelation maps a human-friendly action name to the FGA relation.
func actionToRelation(action string) (string, error) {
	switch action {
	case "execute":
		return "can_execute", nil
	case "configure":
		return "can_configure", nil
	case "read":
		return "can_read", nil
	}
	return "", ErrInvalidAction
}

// normalizeRef ensures the component ref does not include the "component:" prefix
// so we can safely prepend it in tuple construction.
func normalizeRef(ref string) string {
	return strings.TrimPrefix(ref, "component:")
}
