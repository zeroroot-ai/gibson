// Package api — tenant_admin_create.go implements TenantAdminService.CreateAgentIdentity.
//
// Flow (per design.md "CreateAgentIdentity flow with rollback"):
//  1. Validate caller is not itself an agent/tool/plugin principal.
//  2. Validate name regex and kind enum.
//  3. Resolve tenant from context.
//  4. CreateServiceAccount in IdP.
//  5. MintClientSecret (rollback on failure: DeleteServiceAccount).
//  6. AddTenantScopeMembership (rollback on failure: DeleteServiceAccount).
//  7. Write FGA tuples (rollback on failure: DeleteServiceAccount).
//  8. Emit audit event.
//  9. Return response including the one-time client_secret.
//
// Security: client_secret is returned once and NEVER appears in any log line,
// audit event, error message, or trace span.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/idp"
	tenantpb "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
)

// nameRegex is the validation pattern for agent identity names.
// Must start with a lowercase letter, followed by 2-40 lowercase letters, digits, or hyphens.
var nameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{2,40}$`)

// CreateAgentIdentity provisions a new machine identity for an agent, tool, or plugin.
// The returned client_secret is emitted exactly once and must be stored immediately.
func (s *DaemonServer) CreateAgentIdentity(ctx context.Context, req *tenantpb.CreateAgentIdentityRequest) (*tenantpb.CreateAgentIdentityResponse, error) {
	// Step 1: Verify caller is not itself an agent/tool/plugin principal.
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if isNonHumanPrincipal(callerID.Subject) {
		return nil, status_grpc.Error(codes.PermissionDenied,
			"agent, tool, and plugin principals cannot provision new identities")
	}

	// Step 2: Validate name and kind.
	if !nameRegex.MatchString(req.Name) {
		return nil, status_grpc.Errorf(codes.InvalidArgument,
			"name %q is invalid: must match ^[a-z][a-z0-9-]{2,40}$", req.Name)
	}

	idpRole, fgaType, err := principalKindToRole(req.Kind)
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
	}

	// Step 3: Resolve caller's tenant.
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant ID not found in request context")
	}

	// Verify IdP client is wired.
	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable,
			"identity provider not configured; set GIBSON_IDP_PROVIDER and related env vars")
	}

	// Step 4: Create service account in IdP.
	saName := fmt.Sprintf("%s-%s-%s", string(idpRole), tenantID, req.Name)
	sa, err := s.idpAdminClient.CreateServiceAccount(ctx, idp.CreateServiceAccountRequest{
		Name:        saName,
		Description: req.Description,
		Role:        idpRole,
	})
	if err != nil {
		if errors.Is(err, idp.ErrAlreadyExists) {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "an identity named %q of kind %s already exists in this tenant", req.Name, req.Kind)
		}
		s.logger.ErrorContext(ctx, "CreateAgentIdentity: IdP create failed",
			slog.String("tenant_id", tenantID),
			slog.String("name", req.Name),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to create identity in identity provider")
	}

	// Step 5: Mint client secret (rollback on failure).
	clientSecret, err := s.idpAdminClient.MintClientSecret(ctx, sa.AccountID)
	if err != nil {
		s.rollbackServiceAccount(ctx, sa.AccountID, "MintClientSecret failed")
		s.logger.ErrorContext(ctx, "CreateAgentIdentity: MintClientSecret failed",
			slog.String("tenant_id", tenantID),
			slog.String("account_id", sa.AccountID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to generate credentials")
	}

	// Step 6: Add service account to tenant scope membership (rollback on failure).
	if s.authorizer != nil {
		// Derive the tenant scope ID: for the current Zitadel implementation this
		// is the Zitadel project ID, which is embedded in the service account name
		// context. We use the tenantID as the scope identifier here; the concrete
		// zitadel adapter reads GIBSON_IDP_ZITADEL_PROJECT_ID from its own config.
		memberReq := idp.AddMembershipRequest{
			AccountID:     sa.AccountID,
			TenantScopeID: tenantID,
			Role:          idpRole,
		}
		if err := s.idpAdminClient.AddTenantScopeMembership(ctx, memberReq); err != nil {
			s.rollbackServiceAccount(ctx, sa.AccountID, "AddTenantScopeMembership failed")
			s.logger.ErrorContext(ctx, "CreateAgentIdentity: AddTenantScopeMembership failed",
				slog.String("tenant_id", tenantID),
				slog.String("account_id", sa.AccountID),
				slog.String("error", err.Error()),
			)
			return nil, status_grpc.Error(codes.Internal, "failed to configure identity tenant membership")
		}
	}

	// Step 7: Write FGA tuples (rollback on failure).
	principalID := fgaType + ":" + sa.AccountID
	if s.authorizer != nil {
		tuples := []authz.Tuple{
			{
				User:     "user:" + callerID.Subject,
				Relation: "owner",
				Object:   principalID,
			},
			{
				User:     "tenant:" + tenantID,
				Relation: "belongs_to",
				Object:   principalID,
			},
		}

		// Optional component grants.
		for _, cg := range req.ComponentGrants {
			tuples = append(tuples, authz.Tuple{
				User:     principalID,
				Relation: cg.Relation,
				Object:   cg.ComponentRef,
			})
		}

		if err := s.authorizer.Write(ctx, tuples); err != nil {
			s.rollbackServiceAccount(ctx, sa.AccountID, "FGA Write failed")
			s.logger.ErrorContext(ctx, "CreateAgentIdentity: FGA write failed",
				slog.String("tenant_id", tenantID),
				slog.String("principal_id", principalID),
				slog.String("error", err.Error()),
			)
			return nil, status_grpc.Error(codes.Internal, "failed to configure identity authorization")
		}
	}

	// Step 8: Emit audit event (non-fatal — never include client_secret).
	if s.tenantAdminAuditWriter != nil {
		s.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   tenantID,
			ActorID:    callerID.Subject,
			ActorType:  "user",
			Action:     "agent_identity.created",
			TargetType: fgaType,
			TargetID:   sa.AccountID,
			Decision:   "allow",
		})
	}

	// Step 9: Build and return response.
	// The client_secret is included in the response exactly once.
	// It MUST NOT be included in any log line below this point.
	s.logger.InfoContext(ctx, "agent identity created",
		slog.String("tenant_id", tenantID),
		slog.String("principal_id", principalID),
		slog.String("kind", req.Kind.String()),
		slog.String("name", req.Name),
		slog.String("actor", callerID.Subject),
		// client_secret intentionally omitted
	)

	gibsonURL := s.gibsonPublicURL
	enrollCmd := buildEnrollCommand(gibsonURL, sa.AccountID)

	return &tenantpb.CreateAgentIdentityResponse{
		PrincipalId:   principalID,
		Kind:          req.Kind,
		Name:          req.Name,
		ClientId:      sa.AccountID,
		ClientSecret:  clientSecret, // emitted once; caller must store immediately
		GibsonUrl:     gibsonURL,
		EnrollCommand: enrollCmd,
	}, nil
}

// rollbackServiceAccount attempts to delete the service account after a
// partial-provisioning failure. If deletion fails, it logs at ERROR level
// with the leaked_service_account field so an operator can manually clean up.
// Best-effort: we do not retry or block.
func (s *DaemonServer) rollbackServiceAccount(ctx context.Context, accountID, reason string) {
	// Use a background context with a short timeout for the rollback call so a
	// cancelled request context does not prevent cleanup.
	rbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.idpAdminClient.DeleteServiceAccount(rbCtx, accountID); err != nil {
		s.logger.ErrorContext(ctx, "CreateAgentIdentity: rollback failed — service account may be leaked",
			slog.String("leaked_service_account", accountID),
			slog.String("rollback_reason", reason),
			slog.String("rollback_error", err.Error()),
		)
	}
}

// principalKindToRole maps a proto PrincipalKind to the idp.Role and FGA type string.
func principalKindToRole(kind tenantpb.PrincipalKind) (idp.Role, string, error) {
	switch kind {
	case tenantpb.PrincipalKind_PRINCIPAL_KIND_AGENT:
		return idp.RoleAgent, "agent_principal", nil
	case tenantpb.PrincipalKind_PRINCIPAL_KIND_TOOL:
		return idp.RoleTool, "tool_principal", nil
	case tenantpb.PrincipalKind_PRINCIPAL_KIND_PLUGIN:
		return idp.RolePlugin, "plugin_principal", nil
	default:
		return "", "", fmt.Errorf("kind must be AGENT, TOOL, or PLUGIN; got %s", kind)
	}
}

// isNonHumanPrincipal returns true when the subject looks like a machine principal.
// Machine principals follow the pattern "<type>_principal:<id>".
func isNonHumanPrincipal(subject string) bool {
	return strings.HasPrefix(subject, "agent_principal:") ||
		strings.HasPrefix(subject, "tool_principal:") ||
		strings.HasPrefix(subject, "plugin_principal:")
}

// buildEnrollCommand returns a complete copy-pasteable shell invocation for
// enrolling the agent with the daemon.
func buildEnrollCommand(gibsonURL, clientID string) string {
	if gibsonURL == "" {
		gibsonURL = "<gibson-url>"
	}
	return fmt.Sprintf(
		"gibson-cli agent enroll --client-id %s --client-secret <paste-secret> --gibson-url %s",
		clientID, gibsonURL,
	)
}
