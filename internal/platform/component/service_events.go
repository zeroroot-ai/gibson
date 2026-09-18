// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/componentevents"
	"github.com/zeroroot-ai/sdk/auth"
)

// WithEventHub wires the hub WatchComponentEvents reads from (gibson#154).
func (s *ComponentServiceServer) WithEventHub(h *componentevents.Hub) *ComponentServiceServer {
	s.eventHub = h
	return s
}

// WatchComponentEvents streams secret_access_revoked and secret_rotated to
// the calling component (gibson#154, sdk#55). The component is the caller's
// identity: the request names nothing, so a caller cannot watch another
// component. The subscription key is the FGA user the daemon authorizes
// this caller as, the same string the revocation deletes its can_resolve
// tuple under. A heartbeat event keeps the stream visibly alive; the SDK
// drops the type after a debug log.
func (s *ComponentServiceServer) WatchComponentEvents(_ *componentpb.WatchComponentEventsRequest, stream grpc.ServerStreamingServer[componentpb.ComponentEvent]) error {
	if s.eventHub == nil {
		return status.Error(codes.Unavailable, "component event hub not configured")
	}
	ctx := stream.Context()
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		return status.Error(codes.Unauthenticated, "no caller identity")
	}
	principal := componentFGAUser(identity.Subject)
	evCh, unsub := s.eventHub.Subscribe(tenant, principal)
	defer unsub()

	heartbeat := time.NewTicker(s.eventHub.HeartbeatInterval())
	defer heartbeat.Stop()

	s.logger.Info("component events: stream connected", "tenant", tenant, "principal", principal)
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-evCh:
			if !ok {
				return nil
			}
			if err := stream.Send(toProtoEvent(ev)); err != nil {
				return fmt.Errorf("component events: send %s: %w", ev.Type, err)
			}
		case <-heartbeat.C:
			if err := stream.Send(&componentpb.ComponentEvent{Type: componentevents.TypeHeartbeat, OccurredAt: timestamppb.Now()}); err != nil {
				return fmt.Errorf("component events: send heartbeat: %w", err)
			}
		}
	}
}

func toProtoEvent(ev componentevents.Event) *componentpb.ComponentEvent {
	out := &componentpb.ComponentEvent{
		Type:       ev.Type,
		SecretName: ev.SecretName,
		Reason:     ev.Reason,
		Version:    ev.Version,
	}
	if !ev.OccurredAt.IsZero() {
		out.OccurredAt = timestamppb.New(ev.OccurredAt)
	}
	return out
}
