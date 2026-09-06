// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

// Package api — signup_mail_delivery_integration_test.go
//
// CHAIN 2 (SIGNUP) — the mail-delivery half of the exit test.
//
// The board states chain 2 in plain words as "a new customer never receives
// the verification email, so nobody can sign up". Every existing signup test
// asserts against a fake mailer (`fakeSignupMailer` in signup_service_test.go),
// so the one thing the blocker is actually about — that a message leaves the
// daemon, crosses a real SMTP transport and arrives in a real mailbox — has
// never been asserted anywhere.
//
// This test asserts exactly that, and does it through the code the daemon
// runs in production:
//
//   - a real Postgres, migrated by the REAL migration set (021 creates the
//     verification table). Nothing here hand-creates a table: "no manual DB
//     touch" is part of the exit criterion, so a test that seeded its own
//     schema would be asserting a database we do not ship;
//   - a real SMTP server (mailpit) and the real transport built by
//     `mailer.NewFromEnv`, from the same GIBSON_EMAIL_PROVIDER / GIBSON_SMTP_*
//     variables the chart sets;
//   - the real `SignupVerificationStore` and the real RPC handlers.
//
// The token is recovered from the delivered message body, the way a
// recipient's browser would, and redeemed. A token read out of the database
// instead would pass even if the link we mail were malformed.
//
// RUNS WITHOUT STAGING OR PROD, on containers alone.
//
// WHAT THIS DOES NOT CLOSE: the second half of the exit test — "the account
// reaches a Ready workspace". That needs the IdP and provisioning, and is not
// claimed here. Chain 2 stays open until both halves pass.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"
)

const (
	// mailpitImage is the SMTP sink. It is a real SMTP server with an HTTP
	// API for reading what arrived, which is what makes "did it actually get
	// delivered" answerable rather than inferred.
	mailpitImage = "axllent/mailpit:v1.21"

	signupAppURL = "https://app.example.test"
	signupAPIURL = "https://api.example.test"
)

// mailpit is a running SMTP sink plus its read API.
type mailpit struct {
	smtpHost string
	smtpPort string
	apiBase  string
}

// startMailpit boots the sink and returns its SMTP and HTTP endpoints.
func startMailpit(t *testing.T) *mailpit {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        mailpitImage,
		ExposedPorts: []string{"1025/tcp", "8025/tcp"},
		// Wait on the HTTP API rather than on a log line: the API is what the
		// assertions use, so readiness should mean "the thing I am about to
		// call is up", not "a message resembling readiness was printed".
		WaitingFor: wait.ForHTTP("/api/v1/messages").WithPort("8025/tcp").WithStartupTimeout(2 * time.Minute),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("mailpit container unavailable (no Docker?): %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	require.NoError(t, err, "mailpit host")
	smtp, err := c.MappedPort(ctx, "1025")
	require.NoError(t, err, "mailpit smtp port")
	api, err := c.MappedPort(ctx, "8025")
	require.NoError(t, err, "mailpit api port")

	return &mailpit{
		smtpHost: host,
		smtpPort: smtp.Port(),
		apiBase:  fmt.Sprintf("http://%s:%s", host, api.Port()),
	}
}

// mailpitMessage is the subset of the list API this test reads.
type mailpitMessage struct {
	ID      string                     `json:"ID"`
	To      []struct{ Address string } `json:"To"`
	Subject string                     `json:"Subject"`
}

// messages returns everything currently in the sink.
func (m *mailpit) messages(t *testing.T) []mailpitMessage {
	t.Helper()
	resp, err := http.Get(m.apiBase + "/api/v1/messages")
	require.NoError(t, err, "list mailpit messages")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "mailpit list status")

	var body struct {
		Messages []mailpitMessage `json:"messages"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body), "decode mailpit list")
	return body.Messages
}

// waitForMessage polls until exactly one message is addressed to `to`.
//
// Polling rather than a fixed sleep: SMTP delivery is asynchronous and a sleep
// long enough to be reliable is long enough to be slow, while a short one
// turns a real regression into a flake.
func (m *mailpit) waitForMessage(t *testing.T, to string) mailpitMessage {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, msg := range m.messages(t) {
			for _, rcpt := range msg.To {
				if strings.EqualFold(rcpt.Address, to) {
					return msg
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("CHAIN 2 FAILED: no verification mail was delivered to %s within the wait.\n"+
		"This is the blocker in one line: the daemon accepted the signup and the "+
		"customer never received anything.", to)
	return mailpitMessage{}
}

// body returns the rendered text of one message.
func (m *mailpit) body(t *testing.T, id string) string {
	t.Helper()
	resp, err := http.Get(m.apiBase + "/api/v1/message/" + url.PathEscape(id))
	require.NoError(t, err, "fetch mailpit message")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "mailpit message status")

	var body struct {
		Text string `json:"Text"`
		HTML string `json:"HTML"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body), "decode mailpit message")
	return body.Text + "\n" + body.HTML
}

// verifyLinkRE finds the verification URL in a delivered message.
var verifyLinkRE = regexp.MustCompile(`https?://[^\s"'<>]+`)

// tokenFromDeliveredMail recovers the raw token from the message body, the way
// a recipient's browser would.
//
// Deliberately not read from the database. A token taken from the store proves
// the row exists; only a token taken from the mail proves the link we sent is
// usable, which is the property a customer experiences.
func tokenFromDeliveredMail(t *testing.T, body string) string {
	t.Helper()
	for _, raw := range verifyLinkRE.FindAllString(body, -1) {
		raw = strings.TrimRight(raw, ".,)")
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if tok := u.Query().Get("token"); tok != "" {
			require.Truef(t, strings.HasPrefix(raw, signupAppURL),
				"the verification link points at %q, not the product surface %q — "+
					"a link built from the API origin has no route to land on", raw, signupAppURL)
			return tok
		}
	}
	t.Fatalf("no verification link with a token found in the delivered mail:\n%s", body)
	return ""
}

// migratedPlatformDB starts Postgres and applies the real platform migrations.
func migratedPlatformDB(t *testing.T) *sql.DB {
	t.Helper()

	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{})
	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err, "open platform db")
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.Ping(), "ping platform db")

	src, err := pgmigrations.NewPlatformSource()
	require.NoError(t, err, "platform migration source")
	defer func() { _ = src.Close() }()

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	require.NoError(t, err, "migrate driver")

	m, err := migrate.NewWithInstance("iofs", src, "platform", driver)
	require.NoError(t, err, "migrate instance")

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("apply platform migrations: %v", err)
	}
	return db
}

// realSignupServer wires the handlers exactly as the daemon does, with the
// real store and the real SMTP transport.
func realSignupServer(t *testing.T, db *sql.DB, mp *mailpit) *DaemonServer {
	t.Helper()

	// The same variables the chart sets. Building the transport from env is
	// the point: it exercises resolveSignupMailer's contract rather than a
	// hand-assembled client that could diverge from it.
	t.Setenv("GIBSON_EMAIL_PROVIDER", "smtp")
	t.Setenv("GIBSON_SMTP_HOST", mp.smtpHost)
	t.Setenv("GIBSON_SMTP_PORT", mp.smtpPort)
	t.Setenv("GIBSON_EMAIL_FROM", "no-reply@example.test")

	m, err := mailer.NewFromEnv(testSlogLogger)
	require.NoError(t, err, "build mailer from env")
	require.NoError(t, mailer.RequireDelivering(m),
		"the transport built from env must be a DELIVERING one; a log transport would make this test assert nothing")

	srv := &DaemonServer{logger: testSlogLogger}
	srv.signupPolicy = signup.PolicySelfServe
	srv.gibsonPublicURL = signupAPIURL
	srv.WithAppURL(signupAppURL)
	srv.WithSignupVerificationStore(NewSignupVerificationStore(db)).
		WithSignupMailer(mailer.NewVerificationSender(m)).
		WithSignupLimiter(&allowAllLimiter{})
	return srv
}

// TestChain2_VerificationMailIsActuallyDelivered is the mail half of the
// chain-2 exit test.
//
//  1. a signup request for an arbitrary address;
//  2. the message ARRIVES in a real mailbox over real SMTP;
//  3. the token taken FROM THAT MESSAGE redeems into a verified session.
//
// Step 3 is not redundant with step 2. A mail that arrives carrying a dead
// link is indistinguishable from success at the SMTP layer and total failure
// to the customer.
func TestChain2_VerificationMailIsActuallyDelivered(t *testing.T) {
	mp := startMailpit(t)
	db := migratedPlatformDB(t)
	srv := realSignupServer(t, db, mp)

	ctx := context.Background()
	const addr = "chain2-customer@example.test"

	resp, err := srv.RequestEmailVerification(ctx, &tenantv1.RequestEmailVerificationRequest{
		AttemptId:     uuid.NewString(),
		OwnerEmail:    addr,
		WorkspaceName: "Chain Two Ltd",
		Tier:          "team",
		ClientIp:      "203.0.113.10",
	})
	require.NoError(t, err, "RequestEmailVerification")
	require.NotNil(t, resp)

	msg := mp.waitForMessage(t, addr)
	t.Logf("delivered: subject=%q id=%s", msg.Subject, msg.ID)

	token := tokenFromDeliveredMail(t, mp.body(t, msg.ID))

	redeemed, err := srv.RedeemEmailVerification(ctx, &tenantv1.RedeemEmailVerificationRequest{
		Token:    token,
		ClientIp: "203.0.113.10",
	})
	require.NoError(t, err, "the token taken from the delivered mail must redeem")
	require.NotEmpty(t, redeemed.GetVerifiedSessionToken(), "redeem must return a verified session")
	require.Equal(t, addr, redeemed.GetOwnerEmail())

	t.Logf("CHAIN 2 (mail half) PASSED: %s received the verification mail and its link redeemed", addr)
}

// TestChain2_NoTransportRefusesAndLeavesNothingBehind is the failing fixture.
//
// It breaks the property on purpose — no mail transport — and asserts the
// daemon REFUSES rather than accepting a signup it cannot verify. Without this,
// a green run above is also consistent with a handler that never checks.
//
// The residue assertion is the sharp half: a signup that failed must not leave
// a verification row, or a customer who never got mail still occupies the
// address and the resend cooldown locks them out of retrying.
func TestChain2_NoTransportRefusesAndLeavesNothingBehind(t *testing.T) {
	mp := startMailpit(t)
	db := migratedPlatformDB(t)

	srv := &DaemonServer{logger: testSlogLogger}
	srv.signupPolicy = signup.PolicySelfServe
	srv.gibsonPublicURL = signupAPIURL
	srv.WithAppURL(signupAppURL)
	// Everything EXCEPT a mailer.
	srv.WithSignupVerificationStore(NewSignupVerificationStore(db)).
		WithSignupLimiter(&allowAllLimiter{})

	const addr = "chain2-no-transport@example.test"
	_, err := srv.RequestEmailVerification(context.Background(), &tenantv1.RequestEmailVerificationRequest{
		AttemptId:     uuid.NewString(),
		OwnerEmail:    addr,
		WorkspaceName: "No Transport Ltd",
		Tier:          "team",
		ClientIp:      "203.0.113.11",
	})
	require.Error(t, err, "a signup with no mail transport must be refused, not accepted")
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"refusal must be FailedPrecondition: this is a deployment misconfiguration, not a transient condition worth retrying")

	var rows int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM signup_verification WHERE lower(email) = lower($1)`, addr,
	).Scan(&rows), "count verification rows")
	require.Zero(t, rows,
		"a refused signup left a verification row behind; the customer got no mail AND is now rate-limited on their own address")

	require.Empty(t, mp.messages(t), "nothing may be delivered when the transport is absent")
}
