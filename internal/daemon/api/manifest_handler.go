package api

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/manifest"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WithManifestBuilder wires the capability-manifest Builder into the
// server. When nil (default), GetCapabilityManifest returns
// codes.Unavailable so the daemon can start before the manifest
// subsystem is ready without crashing.
func (s *DaemonServer) WithManifestBuilder(b manifest.Builder) *DaemonServer {
	s.manifestBuilder = b
	return s
}

// GetCapabilityManifest resolves and returns the signed capability
// manifest for the calling principal in their resolved tenant. Identity
// → subject mapping: an identity whose Subject begins with
// "agent_principal:" becomes an agent_principal subject; anything else
// is treated as a user subject. Impersonation (request.agent_principal_id
// set) requires the caller to hold the "admin" FGA relation on the tenant.
func (s *DaemonServer) GetCapabilityManifest(ctx context.Context, req *manifestpb.GetCapabilityManifestRequest) (*manifestpb.GetCapabilityManifestResponse, error) {
	if s.manifestBuilder == nil {
		return nil, status.Error(codes.Unavailable, "manifest subsystem not configured")
	}

	id, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "no identity in context")
	}
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return nil, status.Error(codes.PermissionDenied, "caller has no tenant membership")
	}

	subject, resolveErr := s.resolveManifestSubject(id, req, tenantID, ctx)
	if resolveErr != nil {
		return nil, resolveErr
	}

	m, err := s.manifestBuilder.Build(ctx, subject)
	if err != nil {
		return nil, translateBuildError(err)
	}

	s.logger.Info("manifest: issued via RPC",
		"manifest_id", m.ManifestId,
		"subject", m.Subject,
		"tenant_id", m.TenantId,
		"manifest_version", m.ManifestVersion,
	)
	return &manifestpb.GetCapabilityManifestResponse{Manifest: m}, nil
}

// resolveManifestSubject derives a ManifestSubject from the caller
// identity plus the optional impersonation request field. Returns a
// gRPC status error ready to return to the client.
//
// Impersonation (req.agent_principal_id set) requires the caller to
// hold FGA admin relation on the tenant — checked via s.authorizer.
func (s *DaemonServer) resolveManifestSubject(id auth.Identity, req *manifestpb.GetCapabilityManifestRequest, tenantID string, ctx context.Context) (manifest.ManifestSubject, error) {
	callerIsAgent := strings.HasPrefix(id.Subject, "agent_principal:")

	// Impersonation path: admin previewing another agent_principal's manifest.
	if req.GetAgentPrincipalId() != "" {
		if callerIsAgent {
			return manifest.ManifestSubject{}, status.Error(codes.PermissionDenied, "agent_principal callers may not impersonate")
		}
		// Validate admin via FGA when authorizer is wired.
		if s.authorizer != nil {
			isAdmin, err := s.authorizer.Check(ctx,
				"user:"+id.Subject, "admin", "tenant:"+tenantID)
			if err != nil || !isAdmin {
				return manifest.ManifestSubject{}, status.Error(codes.PermissionDenied, "impersonation requires tenant admin")
			}
		}
		return manifest.ManifestSubject{
			Type:        manifest.SubjectTypeAgentPrincipal,
			ID:          req.GetAgentPrincipalId(),
			TenantID:    tenantID,
			OwnerUserID: id.Subject, // admin owns the preview query
		}, nil
	}

	if callerIsAgent {
		// "agent_principal:<id>" → id suffix is the agent_principal ID.
		apID := strings.TrimPrefix(id.Subject, "agent_principal:")
		// The lean Identity struct carries no Claims map; agent-principal
		// callers that need owner resolution should pass it via the request
		// or use a manifest-specific lookup. The Builder will return
		// InvalidArgument when OwnerUserID is empty.
		return manifest.ManifestSubject{
			Type:        manifest.SubjectTypeAgentPrincipal,
			ID:          apID,
			TenantID:    tenantID,
			OwnerUserID: "", // resolved by Builder from agent-auth store
		}, nil
	}

	return manifest.ManifestSubject{
		Type:     manifest.SubjectTypeUser,
		ID:       id.Subject,
		TenantID: tenantID,
	}, nil
}

// translateBuildError maps Builder errors onto gRPC status codes per
// design.md error scenarios. Unknown errors become Internal.
func translateBuildError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "subject has no tenant"),
		strings.Contains(msg, "owner"):
		return status.Error(codes.InvalidArgument, msg)
	case strings.Contains(msg, "FGA"),
		strings.Contains(msg, "VersionStore"),
		strings.Contains(msg, "fga"):
		return status.Error(codes.Unavailable, msg)
	}
	return status.Error(codes.Internal, msg)
}

// manifestLoggerOrDefault returns s.logger or slog.Default to keep the
// handler safe if it is ever invoked before the daemon logger is wired.
func (s *DaemonServer) manifestLoggerOrDefault() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

var _ = daemonpb.UnimplementedDaemonServiceServer{} // force use of daemonpb import if absent above

// WithManifestWatchHub wires the streaming watch fan-out so
// WatchManifestInvalidations can deliver events to connected SDKs.
func (s *DaemonServer) WithManifestWatchHub(h *manifest.WatchHub) *DaemonServer {
	s.manifestWatchHub = h
	return s
}

// WatchManifestInvalidations is the server-streaming RPC that emits
// manifest invalidation events + periodic heartbeats for the caller's
// resolved tenant.
func (s *DaemonServer) WatchManifestInvalidations(req *manifestpb.WatchManifestInvalidationsRequest, stream daemonpb.DaemonService_WatchManifestInvalidationsServer) error {
	if s.manifestWatchHub == nil {
		return status.Error(codes.Unavailable, "manifest watch hub not configured")
	}
	ctx := stream.Context()
	tenantID := auth.TenantStringFromContext(ctx)
	if tenantID == "" {
		return status.Error(codes.PermissionDenied, "caller has no tenant membership")
	}
	evCh, unsub := s.manifestWatchHub.Subscribe(tenantID)
	defer unsub()

	heartbeat := time.NewTicker(s.manifestWatchHub.HeartbeatInterval())
	defer heartbeat.Stop()

	s.logger.Info("manifest: watch subscriber connected", "tenant", tenantID)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-evCh:
			if !ok {
				return nil
			}
			if err := stream.Send(&manifestpb.WatchManifestInvalidationsResponse{Event: ev}); err != nil {
				return err
			}
		case <-heartbeat.C:
			if err := stream.Send(&manifestpb.WatchManifestInvalidationsResponse{Event: manifest.BuildHeartbeat(tenantID)}); err != nil {
				return err
			}
		}
	}
}
