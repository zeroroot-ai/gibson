// Package daemon — billing_service.go
//
// billingServer implements billingpb.BillingServiceServer using the daemon's
// existing platformDB (*sql.DB) — the shared platform Postgres pool wired from
// infrastructure.go.
//
// Two RPCs replace the dashboard's direct pg.Pool usage in the Stripe webhook
// handler (app/api/billing/webhook/route.ts):
//
//   - RecordWebhookEvent — INSERT INTO webhook_idempotency ON CONFLICT DO NOTHING;
//     returns is_new=true only on first delivery so the caller can short-circuit
//     on replay.
//   - DeleteWebhookEvent — DELETE FROM webhook_idempotency WHERE event_id=$1;
//     best-effort rollback when processing fails after the idempotency row was
//     written, allowing Stripe to retry.
//
// The table is created by platform migration 015_webhook_idempotency. Both
// RPCs fail closed (codes.Unavailable) when platformDB is nil.
//
// Tenant-scoping note: the webhook_idempotency table is a platform-level table
// (one row per Stripe event ID, global). It is not per-tenant — Stripe events
// arrive at the platform level. The tenant_id column carries the slug from the
// event metadata for observability only.
//
// Spec: dashboard-no-backing-store-clients (Module 3 — Postgres pool removal).
package daemon

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	billingpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/billing/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	billingQueryTimeout = 5 * time.Second
	webhookTableName    = "webhook_idempotency"
)

// billingServer implements billingpb.BillingServiceServer.
type billingServer struct {
	billingpb.UnimplementedBillingServiceServer

	// dbGetter returns the live platform DB (may return nil before startup).
	dbGetter func() *sql.DB
	logger   *slog.Logger
}

// NewBillingServer constructs a billingServer.
// dbGetter must not be nil. logger may be nil (defaults to slog.Default()).
func NewBillingServer(dbGetter func() *sql.DB, logger *slog.Logger) *billingServer {
	if dbGetter == nil {
		panic("billing server: dbGetter cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &billingServer{
		dbGetter: dbGetter,
		logger:   logger,
	}
}

// requireDB returns the live platform DB or an Unavailable error.
func (s *billingServer) requireDB() (*sql.DB, error) {
	db := s.dbGetter()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform database not yet initialised")
	}
	return db, nil
}

// ---------------------------------------------------------------------------
// RecordWebhookEvent
// ---------------------------------------------------------------------------

// RecordWebhookEvent implements BillingServiceServer.
//
// Inserts the event ID into the idempotency table using INSERT … ON CONFLICT
// DO NOTHING. Returns is_new=true on the first delivery (rowCount=1), false
// on any replay (rowCount=0).
func (s *billingServer) RecordWebhookEvent(
	ctx context.Context,
	req *billingpb.RecordWebhookEventRequest,
) (*billingpb.RecordWebhookEventResponse, error) {
	if req.GetEventId() == "" {
		return nil, status.Error(codes.InvalidArgument, "event_id is required")
	}
	if req.GetEventType() == "" {
		return nil, status.Error(codes.InvalidArgument, "event_type is required")
	}

	// Verify ext-authz context is present (the annotation enforces the member
	// relation, but we perform a belt-and-suspenders tenant extraction to log).
	_, _ = auth.TenantFromContext(ctx) // informational only; not enforced here

	db, err := s.requireDB()
	if err != nil {
		return nil, err
	}

	qctx, cancel := context.WithTimeout(ctx, billingQueryTimeout)
	defer cancel()

	result, dbErr := db.ExecContext(qctx,
		`INSERT INTO "`+webhookTableName+`" (event_id, event_type, tenant_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		req.GetEventId(),
		req.GetEventType(),
		req.GetTenantId(),
	)
	if dbErr != nil {
		s.logger.WarnContext(ctx, "BillingService.RecordWebhookEvent: INSERT failed",
			slog.String("event_id", req.GetEventId()),
			slog.String("event_type", req.GetEventType()),
			slog.String("error", dbErr.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to record webhook event: %v", dbErr)
	}

	rows, _ := result.RowsAffected()
	return &billingpb.RecordWebhookEventResponse{IsNew: rows > 0}, nil
}

// ---------------------------------------------------------------------------
// DeleteWebhookEvent
// ---------------------------------------------------------------------------

// DeleteWebhookEvent implements BillingServiceServer.
//
// Removes an event ID from the idempotency table as a best-effort rollback
// when the webhook handler fails after the idempotency row was written.
// Deletion is idempotent — succeeds even when the event ID does not exist.
func (s *billingServer) DeleteWebhookEvent(
	ctx context.Context,
	req *billingpb.DeleteWebhookEventRequest,
) (*billingpb.DeleteWebhookEventResponse, error) {
	if req.GetEventId() == "" {
		return nil, status.Error(codes.InvalidArgument, "event_id is required")
	}

	db, err := s.requireDB()
	if err != nil {
		return nil, err
	}

	qctx, cancel := context.WithTimeout(ctx, billingQueryTimeout)
	defer cancel()

	if _, dbErr := db.ExecContext(qctx,
		`DELETE FROM "`+webhookTableName+`" WHERE event_id = $1`,
		req.GetEventId(),
	); dbErr != nil {
		s.logger.WarnContext(ctx, "BillingService.DeleteWebhookEvent: DELETE failed",
			slog.String("event_id", req.GetEventId()),
			slog.String("error", dbErr.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to delete webhook event: %v", dbErr)
	}

	return &billingpb.DeleteWebhookEventResponse{}, nil
}

// compile-time interface check.
var _ billingpb.BillingServiceServer = (*billingServer)(nil)
