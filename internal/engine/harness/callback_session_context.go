// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"log/slog"

	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
)

// Session-context store handlers (gibson#1184, sdk v0.162.0).
//
// Put/Get/DeleteSessionContext persist one opaque, versioned blob per
// (tenant, session_id) in the per-tenant dataplane store — the TRUSTED home
// for a component's session-local context, so it never has to live on the
// untrusted Devbox volume. The daemon never interprets the bytes.
//
// The tenant half of the key is derived server-side from the authenticated
// caller's identity (auth.TenantStringFromContext — the identity the auth
// interceptor placed from headers AFTER the per-peer method policy admitted
// the transport peer). No request message carries a tenant field, so a caller
// cannot name another tenant's session: cross-tenant access is
// unrepresentable rather than rejected. session_id is the agent-chosen
// opaque identity shared with DevboxExec (gibson#1183).

// maxSessionContextBytes mirrors the store-side cap
// (internal/infra/database/postgres.MaxSessionContextBytes) so an oversized
// blob is refused before it is shipped to the store. ~8 MB per the resolved
// design; larger working state belongs in the session Devbox.
const maxSessionContextBytes = 8 << 20

// maxSessionIDBytes bounds the agent-chosen opaque session identity. It is a
// storage key (per-tenant Postgres primary key), not content, so a generous
// but finite bound keeps hostile callers from stuffing megabytes into a key
// column while never constraining any legitimate ID scheme.
const maxSessionIDBytes = 256

// ErrSessionContextConflict is returned by a SessionContextStore when the
// etag compare-and-swap fails: an empty if_match ("create") found an existing
// blob, or a non-empty if_match named a version that is no longer current.
// The handler surfaces it as codes.Aborted.
var ErrSessionContextConflict = errors.New("session context: etag conflict")

// ErrSessionContextTooLarge is returned by a SessionContextStore when the
// blob exceeds the store's size cap. The handler surfaces it as
// codes.ResourceExhausted. The handler's own maxSessionContextBytes check
// makes this a second line of defense.
var ErrSessionContextTooLarge = errors.New("session context: blob too large")

// SessionContextStore is the persistence seam for the session-context RPCs.
// The daemon wires an implementation backed by the per-tenant dataplane
// Postgres (envelope-encrypted under the tenant KEK); nil means the store is
// not available on this daemon and the RPCs return Unavailable.
//
// Contract (mirrors the wire contract in harness_callback.proto):
//   - Put: ifMatch=="" is create-only (fails with ErrSessionContextConflict
//     when a live blob exists); a non-empty ifMatch must name the current
//     version. Returns the etag of the version the write produced.
//   - Get: a missing blob is NOT an error — (nil, "", nil).
//   - Delete: deleting a missing blob is a no-op, not an error.
//
// Implementations must scope all storage to the given tenant such that no
// (tenant A) call can observe (tenant B) state.
type SessionContextStore interface {
	Put(ctx context.Context, tenant, sessionID string, data []byte, ifMatch string) (etag string, err error)
	Get(ctx context.Context, tenant, sessionID string) (data []byte, etag string, err error)
	Delete(ctx context.Context, tenant, sessionID string) error
}

// sessionCallerTenant resolves the authenticated caller's tenant for the
// session RPCs, failing closed exactly as authorizeCredentialResolve does: no
// identity-derived tenant, or the system-tenant sentinel, is a deny — the
// session key is (tenant, session_id) and a request without a real tenant has
// no session namespace to operate in.
func (s *HarnessCallbackService) sessionCallerTenant(ctx context.Context, rpc string) (string, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		s.logger.WarnContext(ctx, "session context: no tenant in caller identity",
			slog.String("rpc", rpc))
		return "", status.Error(codes.PermissionDenied,
			rpc+": denied: no tenant in caller identity")
	}
	return tenant, nil
}

// validateSessionID applies the shared session_id hygiene for all session
// RPCs: required, and bounded (it is a storage key, not content).
func validateSessionID(rpc, sessionID string) error {
	if sessionID == "" {
		return status.Error(codes.InvalidArgument, rpc+": session_id is required")
	}
	if len(sessionID) > maxSessionIDBytes {
		return status.Errorf(codes.InvalidArgument,
			"%s: session_id exceeds %d bytes", rpc, maxSessionIDBytes)
	}
	return nil
}

// PutSessionContext writes the caller's session-context blob under etag
// compare-and-swap (empty if_match = create-only), returning the etag of the
// version this write produced.
func (s *HarnessCallbackService) PutSessionContext(ctx context.Context, req *harnesspb.PutSessionContextRequest) (*harnesspb.PutSessionContextResponse, error) {
	if s.sessionContextStore == nil {
		return nil, status.Error(codes.Unavailable,
			"PutSessionContext: session-context store is not wired on this daemon")
	}
	tenant, err := s.sessionCallerTenant(ctx, "PutSessionContext")
	if err != nil {
		return nil, err
	}
	if err := validateSessionID("PutSessionContext", req.GetSessionId()); err != nil {
		return nil, err
	}
	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "PutSessionContext: data is required")
	}
	if len(req.GetData()) > maxSessionContextBytes {
		return nil, status.Errorf(codes.ResourceExhausted,
			"PutSessionContext: data is %d bytes; the cap is %d bytes — keep larger working state in the session Devbox",
			len(req.GetData()), maxSessionContextBytes)
	}

	etag, err := s.sessionContextStore.Put(ctx, tenant, req.GetSessionId(), req.GetData(), req.GetIfMatch())
	if err != nil {
		switch {
		case errors.Is(err, ErrSessionContextConflict):
			// A stale writer must learn it lost the race, distinguishably:
			// Aborted is the canonical optimistic-concurrency failure.
			return nil, status.Errorf(codes.Aborted,
				"PutSessionContext: stale if_match %q (or create raced an existing blob) — Get the current version and retry",
				req.GetIfMatch())
		case errors.Is(err, ErrSessionContextTooLarge):
			return nil, status.Error(codes.ResourceExhausted,
				"PutSessionContext: blob exceeds the store's size cap")
		default:
			s.logger.ErrorContext(ctx, "session context: put failed",
				slog.String("tenant", tenant), slog.String("error", err.Error()))
			return nil, status.Error(codes.Internal, "PutSessionContext: store write failed")
		}
	}
	return &harnesspb.PutSessionContextResponse{Etag: etag}, nil
}

// GetSessionContext reads the caller's session-context blob. A fresh session
// (no blob) is not an error: data is empty and etag "".
func (s *HarnessCallbackService) GetSessionContext(ctx context.Context, req *harnesspb.GetSessionContextRequest) (*harnesspb.GetSessionContextResponse, error) {
	if s.sessionContextStore == nil {
		return nil, status.Error(codes.Unavailable,
			"GetSessionContext: session-context store is not wired on this daemon")
	}
	tenant, err := s.sessionCallerTenant(ctx, "GetSessionContext")
	if err != nil {
		return nil, err
	}
	if err := validateSessionID("GetSessionContext", req.GetSessionId()); err != nil {
		return nil, err
	}

	data, etag, err := s.sessionContextStore.Get(ctx, tenant, req.GetSessionId())
	if err != nil {
		s.logger.ErrorContext(ctx, "session context: get failed",
			slog.String("tenant", tenant), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "GetSessionContext: store read failed")
	}
	return &harnesspb.GetSessionContextResponse{Data: data, Etag: etag}, nil
}

// DeleteSessionContext removes the caller's session-context blob. Deleting a
// session that has no blob is a no-op, not an error.
func (s *HarnessCallbackService) DeleteSessionContext(ctx context.Context, req *harnesspb.DeleteSessionContextRequest) (*harnesspb.DeleteSessionContextResponse, error) {
	if s.sessionContextStore == nil {
		return nil, status.Error(codes.Unavailable,
			"DeleteSessionContext: session-context store is not wired on this daemon")
	}
	tenant, err := s.sessionCallerTenant(ctx, "DeleteSessionContext")
	if err != nil {
		return nil, err
	}
	if err := validateSessionID("DeleteSessionContext", req.GetSessionId()); err != nil {
		return nil, err
	}

	if err := s.sessionContextStore.Delete(ctx, tenant, req.GetSessionId()); err != nil {
		s.logger.ErrorContext(ctx, "session context: delete failed",
			slog.String("tenant", tenant), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "DeleteSessionContext: store delete failed")
	}
	return &harnesspb.DeleteSessionContextResponse{}, nil
}
