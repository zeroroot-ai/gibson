// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// signup_step.go is the neutral external signup step (ADR-0060, D54,
// gibson#713).
//
// With a signup step URL in config, Signup enqueues the new tenant in status
// 'waiting_step' and returns the URL with an opaque token. A component outside
// this repository runs the step and reports the outcome through
// ConnectionPointService.CompleteSignupStep. 'done' moves the row to 'pending',
// where the operator drain sees it. 'failed' moves it to 'step_failed', and a
// later 'done' with the same token is still accepted until the token expires.
//
// With no URL, Signup enqueues the tenant as 'pending' and never waits.
//
// The token is 32 random bytes. Only its SHA-256 hash is stored, so a copy of
// the database cannot complete a step. The token names one signup row and no
// request field can point it at another.

// EnvSignupStepURL is the config of the step URL. Empty means no step.
const EnvSignupStepURL = "GIBSON_SIGNUP_STEP_URL"

// signupStepTTL is how long a step token stays valid.
const signupStepTTL = 24 * time.Hour

// signupStepHold is the hold that Signup puts on a new tenant row.
type signupStepHold struct {
	attemptID string
	tokenHash string
	expiresAt time.Time
}

// newSignupStepToken returns a new opaque token and its stored hash.
func newSignupStepToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("signup step: read random token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashSignupStepToken(token), nil
}

// hashSignupStepToken is the stored form of a token.
func hashSignupStepToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// WithSignupStepURL sets the URL of the external signup step. An empty or
// blank value turns the step off: signup never waits.
func (s *DaemonServer) WithSignupStepURL(u string) *DaemonServer {
	s.signupStepURL = strings.TrimSpace(u)
	return s
}

// signupStepConfigured reports whether signup has an external step.
func (s *DaemonServer) signupStepConfigured() bool { return s.signupStepURL != "" }

// holdForSignupStep returns the hold for a new signup and the token to give
// the browser. It returns a nil hold when no step is configured.
func (s *DaemonServer) holdForSignupStep(attemptID string) (*signupStepHold, string, error) {
	if !s.signupStepConfigured() {
		return nil, "", nil
	}
	token, hash, err := newSignupStepToken()
	if err != nil {
		return nil, "", err
	}
	return &signupStepHold{
		attemptID: attemptID,
		tokenHash: hash,
		expiresAt: time.Now().Add(signupStepTTL),
	}, token, nil
}

// errSignupStepNotFound is the refusal for an unknown or expired token.
var errSignupStepNotFound = errors.New("signup step: no such token")

// completeSignupStep records the outcome of the step of the row that the
// token names. done moves a waiting or failed row to 'pending'. A failed
// outcome moves a waiting row to 'step_failed'. A row that is already past
// the step is not changed, and the call succeeds, so a retry is safe.
func completeSignupStep(ctx context.Context, db *sql.DB, token string, done bool, now time.Time) error {
	const q = `
		UPDATE pending_tenant_provisioning
		SET status = CASE WHEN $2 THEN 'pending' ELSE 'step_failed' END,
		    updated_at = NOW()
		WHERE step_token_hash = $1
		  AND step_expires_at > $3
		  AND status IN ('waiting_step', 'step_failed')
	`
	hash := hashSignupStepToken(token)
	res, err := db.ExecContext(ctx, q, hash, done, now)
	if err != nil {
		return fmt.Errorf("signup step: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// No row moved. Either the token is unknown or expired, or the row is
	// already past the step. Only the first is a refusal.
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM pending_tenant_provisioning
		                WHERE step_token_hash = $1 AND status IN ('pending', 'claimed', 'done'))`,
		hash,
	).Scan(&exists); err != nil {
		return fmt.Errorf("signup step: read: %w", err)
	}
	if !exists {
		return errSignupStepNotFound
	}
	return nil
}

// signupStepState reads the state of the step of one signup attempt. An
// unknown attempt, or one with no step, is NONE.
func signupStepState(ctx context.Context, db *sql.DB, attemptID string) (tenantv1.SignupStepState, error) {
	var queueStatus, tokenHash string
	err := db.QueryRowContext(ctx,
		`SELECT status, step_token_hash FROM pending_tenant_provisioning WHERE attempt_id = $1`,
		attemptID,
	).Scan(&queueStatus, &tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_NONE, nil
	}
	if err != nil {
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_UNSPECIFIED, fmt.Errorf("signup step: read state: %w", err)
	}
	return stepStateOf(queueStatus, tokenHash), nil
}

// stepStateOf maps a queue row to the state of its step.
func stepStateOf(queueStatus, tokenHash string) tenantv1.SignupStepState {
	switch {
	case tokenHash == "":
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_NONE
	case queueStatus == "waiting_step":
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_WAITING
	case queueStatus == "step_failed":
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_FAILED
	default:
		return tenantv1.SignupStepState_SIGNUP_STEP_STATE_DONE
	}
}

// GetSignupStep implements SignupServiceServer. The attempt id is the
// capability, as for GetSignupProgress, and an unknown attempt reads as NONE.
func (s *DaemonServer) GetSignupStep(ctx context.Context, req *tenantv1.GetSignupStepRequest) (*tenantv1.GetSignupStepResponse, error) {
	if !isUUID(req.GetAttemptId()) {
		return nil, status.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	state, err := signupStepState(ctx, db, req.GetAttemptId())
	if err != nil {
		s.logger.ErrorContext(ctx, "GetSignupStep: read failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "signup is temporarily unavailable; please try again shortly")
	}
	return &tenantv1.GetSignupStepResponse{State: state}, nil
}
