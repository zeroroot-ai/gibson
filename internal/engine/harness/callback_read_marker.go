// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// Read markers (gibson#1569). An agent that reads the results of a Connector
// in a loop records how far it read. The daemon keeps each marker as an event
// of the Timeline of the tenant.
//
// The key of a marker is the tenant, the authenticated identity of the caller
// and the Connector. The tenant and the identity come from the auth context.
// The key never holds a field of ContextInfo (agent_name, mission_id),
// because the caller sets those fields. So one component reads only its own
// marker, and no value in the request moves a read or a write to the marker of
// another component.

// ReadMarkerStore is the seam to the Timeline for the read marker RPCs. The
// daemon wires it to the brain of each tenant. nil means this daemon keeps no
// read markers.
type ReadMarkerStore interface {
	// WriteReadMarker appends one marker event and returns after the World
	// holds it, so a read that follows sees the write.
	WriteReadMarker(ctx context.Context, tenant string, m brain.ReadMarker) error
	// LastReadMarker returns the last marker of the subject for the Connector.
	// The bool is false when the subject wrote none.
	LastReadMarker(ctx context.Context, tenant, subject, connector string) (brain.ReadMarker, bool, error)
}

// BrainReadMarkerStore serves the read marker RPCs from the Timeline of the
// tenant. A write is one ReadMarkerWritten event. A read returns the last
// marker of the subject for the Connector from the World.
type BrainReadMarkerStore struct{ reg *brain.Registry }

// NewBrainReadMarkerStore returns the store that the daemon wires.
func NewBrainReadMarkerStore(reg *brain.Registry) *BrainReadMarkerStore {
	return &BrainReadMarkerStore{reg: reg}
}

// WriteReadMarker implements ReadMarkerStore.
func (b *BrainReadMarkerStore) WriteReadMarker(ctx context.Context, tenant string, m brain.ReadMarker) error {
	if b.reg == nil {
		return errors.New("harness: no Timeline for the read marker")
	}
	if err := b.reg.For(tenant).SubmitAndWait(ctx, brain.ReadMarkerWritten(m)); err != nil {
		return fmt.Errorf("fold the read marker: %w", err)
	}
	return nil
}

// LastReadMarker implements ReadMarkerStore.
func (b *BrainReadMarkerStore) LastReadMarker(
	_ context.Context, tenant, subject, connector string,
) (brain.ReadMarker, bool, error) {
	if b.reg == nil {
		return brain.ReadMarker{}, false, errors.New("harness: no Timeline for the read marker")
	}
	m, ok := b.reg.For(tenant).LastReadMarker(subject, connector)
	return m, ok, nil
}

// WithReadMarkerStore sets the store of the read marker RPCs.
func WithReadMarkerStore(store ReadMarkerStore) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.readMarkers = store
	}
}

// SetReadMarkerStore wires the read marker RPCs to the Timeline. Call after
// NewCallbackManager, before Start(). Thread-safe.
func (m *CallbackManager) SetReadMarkerStore(store ReadMarkerStore) {
	if m.server != nil && m.server.service != nil {
		m.server.service.mu.Lock()
		defer m.server.service.mu.Unlock()
		WithReadMarkerStore(store)(m.server.service)
	}
}

func readMarkerError(code commonpb.ErrorCode, msg string) *harnesspb.HarnessError {
	return &harnesspb.HarnessError{Code: code, Message: msg}
}

// readMarkerCaller returns the tenant and the subject of the authenticated
// caller. It fails closed when either is missing.
func readMarkerCaller(ctx context.Context) (tenant, subject string, refusal *harnesspb.HarnessError) {
	tenant = auth.TenantStringFromContext(ctx)
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" || tenant == "" || tenant == auth.SystemTenantString {
		return "", "", readMarkerError(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"the call has no authenticated component identity")
	}
	return tenant, id.Subject, nil
}

// The size of a marker is bounded, so one agent cannot grow the Timeline or the
// World with a large marker. The caps hold for the cursor, for the count of
// the result ids and for the length of each id.
const (
	maxReadMarkerCursor    = 1024
	maxReadMarkerResultIDs = 500
	maxReadMarkerResultID  = 512
)

// readMarkerTooLarge returns why a request is over the caps, or "".
func readMarkerTooLarge(req *harnesspb.WriteReadMarkerRequest) string {
	if len(req.GetCursor()) > maxReadMarkerCursor {
		return fmt.Sprintf("cursor is over %d bytes", maxReadMarkerCursor)
	}
	if len(req.GetResultIds()) > maxReadMarkerResultIDs {
		return fmt.Sprintf("result_ids holds more than %d ids", maxReadMarkerResultIDs)
	}
	for _, id := range req.GetResultIds() {
		if len(id) > maxReadMarkerResultID {
			return fmt.Sprintf("a result id is over %d bytes", maxReadMarkerResultID)
		}
	}
	return ""
}

// readMarkerWriteWait bounds the wait of a write for the fold of the marker.
const readMarkerWriteWait = 10 * time.Second

// WriteReadMarker records a marker for one Connector under the identity of the
// caller.
func (s *HarnessCallbackService) WriteReadMarker(
	ctx context.Context, req *harnesspb.WriteReadMarkerRequest,
) (*harnesspb.WriteReadMarkerResponse, error) {
	if s.readMarkers == nil {
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "this daemon keeps no read markers")}, nil
	}
	tenant, subject, refusal := readMarkerCaller(ctx)
	if refusal != nil {
		return &harnesspb.WriteReadMarkerResponse{Error: refusal}, nil
	}
	if req.GetConnector() == "" {
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "connector is required")}, nil
	}
	if why := readMarkerTooLarge(req); why != "" {
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "the marker is too large: "+why)}, nil
	}
	// The connector must be one of the tenant. A marker for a name that the
	// tenant has no connector for would grow the Timeline with no meaning.
	known, err := s.tenantHasConnector(ctx, tenant, req.GetConnector())
	if err != nil {
		s.logger.ErrorContext(ctx, "the connectors of the tenant are not readable",
			slog.String("tenant", tenant), slog.Any("error", err))
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the daemon could not read the connectors of the tenant")}, nil
	}
	if !known {
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "the tenant has no connector with this name")}, nil
	}
	// A write that holds the marker that is already there changes nothing, so
	// an agent that polls in a loop does not grow the Timeline.
	if last, found, lerr := s.readMarkers.LastReadMarker(ctx, tenant, subject, req.GetConnector()); lerr == nil && found &&
		last.Cursor == req.GetCursor() && slices.Equal(last.ResultIDs, req.GetResultIds()) {
		return &harnesspb.WriteReadMarkerResponse{}, nil
	}
	waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readMarkerWriteWait)
	defer cancel()
	err = s.readMarkers.WriteReadMarker(waitCtx, tenant, brain.ReadMarker{
		Subject:            subject,
		Connector:          req.GetConnector(),
		Cursor:             req.GetCursor(),
		ResultIDs:          append([]string(nil), req.GetResultIds()...),
		RecordedAtUnixNano: time.Now().UnixNano(),
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "the read marker is not on the Timeline",
			slog.String("tenant", tenant), slog.String("connector", req.GetConnector()), slog.Any("error", err))
		return &harnesspb.WriteReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_INTERNAL, "the daemon could not record the marker")}, nil
	}
	return &harnesspb.WriteReadMarkerResponse{}, nil
}

// LastReadMarker returns the last marker that the caller wrote for one
// Connector. A read that fails sets error and never found = false with no
// error, because the agent would then read every result again.
func (s *HarnessCallbackService) LastReadMarker(
	ctx context.Context, req *harnesspb.LastReadMarkerRequest,
) (*harnesspb.LastReadMarkerResponse, error) {
	if s.readMarkers == nil {
		return &harnesspb.LastReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "this daemon keeps no read markers")}, nil
	}
	tenant, subject, refusal := readMarkerCaller(ctx)
	if refusal != nil {
		return &harnesspb.LastReadMarkerResponse{Error: refusal}, nil
	}
	if req.GetConnector() == "" {
		return &harnesspb.LastReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "connector is required")}, nil
	}
	m, found, err := s.readMarkers.LastReadMarker(ctx, tenant, subject, req.GetConnector())
	if err != nil {
		s.logger.ErrorContext(ctx, "the read marker is not readable",
			slog.String("tenant", tenant), slog.String("connector", req.GetConnector()), slog.Any("error", err))
		return &harnesspb.LastReadMarkerResponse{Error: readMarkerError(
			commonpb.ErrorCode_ERROR_CODE_INTERNAL, "the daemon could not read the marker")}, nil
	}
	if !found {
		return &harnesspb.LastReadMarkerResponse{}, nil
	}
	return &harnesspb.LastReadMarkerResponse{
		Found: true,
		Marker: &harnesspb.ReadMarker{
			Connector: m.Connector,
			Cursor:    m.Cursor,
			ResultIds: m.ResultIDs,
			At:        timestamppb.New(time.Unix(0, m.RecordedAtUnixNano).UTC()),
		},
	}, nil
}

// tenantHasConnector reports whether the tenant has a connector with the name.
// It reads the connectors of the tenant through the one MCP client of the
// daemon. A daemon with no client cannot tell, and the write fails.
func (s *HarnessCallbackService) tenantHasConnector(ctx context.Context, tenant, name string) (bool, error) {
	if s.connectors == nil {
		return false, errors.New("this daemon has no connector client")
	}
	tools, err := s.connectors.ListConnectorTools(ctx, tenant)
	if err != nil {
		return false, fmt.Errorf("list the connectors of the tenant: %w", err)
	}
	for _, t := range tools {
		if t.Connector == name {
			return true, nil
		}
	}
	return false, nil
}
