// Package api — tenant_admin_create.go implements TenantAdminService.CreateAgentIdentity.
//
// Flow (per design.md "CreateAgentIdentity flow with rollback"):
//  1. Validate caller is not itself an agent/tool/plugin principal.
//  2. Validate name regex and kind enum.
//  3. Resolve tenant from context.
//  4. CreateServiceAccount in IdP (the canonical numeric sub the FGA principal
//     and the capability-grant JWT key on).
//  5. Write FGA tuples (rollback on failure: DeleteServiceAccount).
//  6. Mint a one-time capability-grant bootstrap token (rollback on failure).
//  7. Emit audit event.
//  8. Return response carrying the bootstrap token (+ enroll_command).
//
// There is NO OAuth2 client_credentials step. Under the unified-identity model
// (ADR-0045) every component kind — agent, tool, plugin — enrolls through the
// one capability-grant handshake: the bootstrap token minted here is exchanged
// by `gibson component register --token` for an Ed25519 host key, and the
// component then signs a per-RPC CG-JWT. No Zitadel OAuth client is provisioned;
// the service account exists only to anchor the canonical sub.
//
// There is no IdP project/role membership step. FGA tuples (step 5) are the
// sole authority for a non-human principal's tenancy and permissions; the IdP
// only anchors the machine user's identity. See gibson#605, gibson#670.
//
// Security: the bootstrap token is returned once and NEVER appears in any log
// line, audit event, error message, or trace span.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/audit"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/idp"
	tenantpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
)

// nameRegex is the validation pattern for agent identity names.
// Must start with a lowercase letter, followed by 2-40 lowercase letters, digits, or hyphens.
var nameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]{2,40}$`)

// CreateAgentIdentity provisions a new machine identity for an agent, tool, or plugin.
// The returned bootstrap token is emitted exactly once and must be stored immediately.
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

	// Step 5: Write FGA tuples (rollback on failure).
	//
	// FGA is the sole authority for a non-human principal's tenancy and
	// permissions: the `tenant:<id> belongs_to <kind>_principal:<sub>` tuple
	// below is what scopes this identity to its tenant, and component grants
	// are what gate what it may do. The IdP (Zitadel) only authenticates the
	// machine user — it is deliberately NOT a tenancy or authorization
	// authority, so there is no project/role membership step. ext-authz
	// reads the `gibson:tenant` claim + these FGA tuples (and capability-grant
	// JWTs); it never consults an IdP project-role claim for a principal.
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
			// Tenant membership: makes the principal a `member` of its tenant so
			// rule-mode client RPCs (e.g. IdentityService/WhoAmI, member-on-
			// tenant) authorize when the component presents its CG-JWT (ADR-0045).
			// The model already lists <kind>_principal as an allowed tenant
			// member; ext-authz's COMPONENT identity-class gate bounds which RPCs
			// this unlocks, so membership is not a broad grant.
			{
				User:     principalID,
				Relation: "member",
				Object:   "tenant:" + tenantID,
			},
		}

		// ADR-0046: capability is enrollment policy, not a type-system wall.
		// One kind->grant table (clientCapabilityGrants) decides what each kind
		// receives beyond the base identity tuples. Agents and tools are
		// clients/invokers (ADR-0045: "server AND client") and are granted
		// execute on the synthetic system backplane (component:_system) so their
		// CG-JWT authorizes the COMPONENT-identity client RPCs via ext-authz's
		// per-method FGA check; plugins are invoked-only (server) and receive no
		// client grant. The universal `tenant_enabled component:_system` baseline
		// (catalog fan-out) satisfies in_tenant_catalog; the per-principal grant
		// here is the real gate.
		tuples = append(tuples, clientCapabilityGrants(principalID, fgaType)...)

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

	// Step 6: Emit audit event (non-fatal — never include the bootstrap token).
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

	// Step 7: Mint the first-registration capability-grant bootstrap token
	// (gibson#648 / ADR-0045) and build the response. The bootstrap token is the
	// component's ONLY credential — it is exchanged by `gibson component register
	// --token` for an Ed25519 host key. It MUST NOT appear in any log line below.
	//
	// The CG Minter is required: under the unified-identity model the bootstrap
	// token is the sole enrollment credential for every kind, so a missing or
	// failing minter is a fail-loud condition (rollback the service account
	// rather than leak a credential-less principal).
	kindStr := strings.TrimSuffix(fgaType, "_principal")
	if s.cgMinter == nil {
		s.rollbackServiceAccount(ctx, sa.AccountID, "CG minter not configured")
		s.logger.ErrorContext(ctx, "CreateAgentIdentity: capability-grant minter not configured",
			slog.String("tenant_id", tenantID),
			slog.String("principal_id", principalID),
		)
		return nil, status_grpc.Error(codes.Unavailable,
			"capability-grant minter not configured; cannot issue enrollment credential")
	}
	bootstrapToken, btErr := s.cgMinter.MintBootstrapToken(capabilitygrant.BootstrapClaims{
		TenantID:    tenantID,
		OwnerUserID: callerID.Subject,
		PrincipalID: principalID,
		Kind:        kindStr,
		Name:        req.Name,
	}, 0)
	if btErr != nil {
		s.rollbackServiceAccount(ctx, sa.AccountID, "MintBootstrapToken failed")
		s.logger.ErrorContext(ctx, "CreateAgentIdentity: bootstrap token mint failed",
			slog.String("tenant_id", tenantID),
			slog.String("principal_id", principalID),
			slog.String("error", btErr.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to generate enrollment credential")
	}

	s.logger.InfoContext(ctx, "agent identity created",
		slog.String("tenant_id", tenantID),
		slog.String("principal_id", principalID),
		slog.String("kind", req.Kind.String()),
		slog.String("name", req.Name),
		slog.String("actor", callerID.Subject),
		// bootstrap token intentionally omitted
	)

	gibsonURL := s.gibsonPublicURL
	enrollCmd := buildEnrollCommand(kindStr)

	return &tenantpb.CreateAgentIdentityResponse{
		PrincipalId:    principalID,
		Kind:           req.Kind,
		Name:           req.Name,
		GibsonUrl:      gibsonURL,
		EnrollCommand:  enrollCmd,
		BootstrapToken: bootstrapToken, // sole enrollment credential (ADR-0045, gibson#670)
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

// clientCapabilityGrants is the single kind->grant policy table (ADR-0046):
// the capability tuples written at enrollment beyond the base identity tuples
// (owner / belongs_to / member), keyed by FGA principal type.
//
//   - agent_principal, tool_principal — clients/invokers (ADR-0045: an agent or
//     tool is "server AND client"). Granted direct_execute on the system
//     backplane (component:_system) so their CG-JWT authorizes the
//     COMPONENT-identity client RPCs (RunMission, CallTool, the
//     mission-management surface).
//   - plugin_principal — invoked-only (server). No client grant; a plugin
//     receives work and answers, it does not drive the platform.
//
// This is the one auditable place that answers "what does each kind get at
// enrollment." Tool/plugin principals are valid grantees for these relations
// as of the symmetric model (gibson#659).
func clientCapabilityGrants(principalID, fgaType string) []authz.Tuple {
	switch fgaType {
	case "agent_principal", "tool_principal":
		return []authz.Tuple{
			{User: principalID, Relation: "direct_execute", Object: "component:_system"},
		}
	default: // plugin_principal — invoked-only
		return nil
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
// registering the component install with the daemon.
//
// The verb is `gibson component register` — the ADK CLI command that *consumes*
// an already-issued bootstrap token and runs the capability-grant handshake
// (ADR-0045), writing the local host key + runtime credential. It is
// deliberately NOT `gibson agent enroll`: that command *provisions a new*
// identity (it calls CreateAgentIdentity again). `--token -` reads the
// bootstrap token from stdin so it never lands in shell history. The same
// command serves every kind; only --kind differs.
func buildEnrollCommand(kind string) string {
	if kind == "" {
		kind = "<kind>"
	}
	return fmt.Sprintf("gibson component register --kind %s --token -", kind)
}
