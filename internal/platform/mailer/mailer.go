// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mailer is a vendor-neutral transactional-email sender for the daemon.
//
// gibson#632: MembershipService.InviteMember / ResendInvitation send the
// invitation accept-link email from the daemon (the invitation lifecycle moved
// off the tenant-operator saga in gibson#626). All daemon code that needs to
// send mail programs against the Mailer interface; concrete transports
// (SMTP, log) live behind NewFromEnv.
//
// The provider is selected at construction from the environment. There is no
// default: GIBSON_EMAIL_PROVIDER must name a transport explicitly. An operator
// who wants the non-delivering dev stub opts into it with provider=log, and
// that stub reports every Send as a failure so no caller can mistake "logged"
// for "delivered".
//
// # Transport honesty
//
// A Mailer reports whether it actually hands the message to a mail system
// (Delivers). Only SMTPMailer does. LogMailer is a local development stub that
// drops the message; it exists so a workstation can exercise the code path
// without an SMTP server, and it is NEVER a valid transport for a flow whose
// security depends on the message arriving.
//
// Two rules follow, and both are enforced here rather than left to callers:
//
//  1. A non-delivering transport never writes a message body, subject line
//     aside, to any sink. Bodies carry single-use links and other capabilities;
//     a log line is a durable, widely-readable sink, so a body in a log is a
//     disclosed capability. LogMailer logs recipient, subject and body length,
//     and nothing else.
//
//  2. There is no implicit provider. GIBSON_EMAIL_PROVIDER must be set
//     explicitly. An unset provider used to mean "log", which turned every
//     misconfigured deployment into one that silently sent no mail; it is now
//     a configuration error.
//
// Callers whose correctness depends on delivery call RequireDelivering to
// decide whether they have one. Neither daemon caller treats the absence as
// fatal to startup: internal/server/daemon/signup_mailer.go and grpc.go warn
// once and leave the dependent feature unwired, so the affected surface
// refuses its own calls (see api.DaemonServer.RequestEmailVerification)
// rather than the whole daemon refusing to boot.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Message is a single transactional email. HTML is optional; Text is required.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Mailer sends transactional email. Implementations must be safe for concurrent
// use.
type Mailer interface {
	Send(ctx context.Context, msg Message) error

	// Delivers reports whether Send hands the message to a mail system.
	//
	// It is part of the interface, not a type assertion callers can forget,
	// because "did this message actually go anywhere" is the only question that
	// matters to a flow built on proof of mailbox control. A transport that
	// returns false accepts messages and discards them.
	Delivers() bool
}

// ErrNoDeliveringTransport is returned by RequireDelivering when the configured
// transport does not deliver. It is a startup error: the surfaces that call it
// have no correct degraded mode.
var ErrNoDeliveringTransport = errors.New("mailer: configured transport does not deliver mail")

// RequireDelivering returns nil only when m is a transport that actually sends.
//
// Use it at construction time for any surface whose security or usability rests
// on the recipient receiving the message — self-serve signup verification above
// all. It reports the gap; it does not decide what the caller does about it. A
// daemon that tells people to check an inbox nothing was sent to is worse than
// one that says plainly, per request, that signup is unavailable — but taking
// the whole platform down over a mail misconfiguration is worse still, so
// gibson's own callers degrade rather than refuse to start (gibson#1228 / PR
// #1228): see internal/server/daemon/signup_mailer.go.
func RequireDelivering(m Mailer) error {
	if m == nil {
		return fmt.Errorf("%w: no transport configured", ErrNoDeliveringTransport)
	}
	if !m.Delivers() {
		return fmt.Errorf("%w: %s=%q accepts messages and discards them; set %s=smtp and %s",
			ErrNoDeliveringTransport, envProvider, providerLog, envProvider, envSMTPHost)
	}
	return nil
}

// Env var names. The provider gates which transport NewFromEnv builds. There is
// no default — see ErrProviderUnset.
const (
	envProvider      = "GIBSON_EMAIL_PROVIDER" // "smtp" | "log" (non-delivering dev stub)
	envFrom          = "GIBSON_EMAIL_FROM"
	envSMTPHost      = "GIBSON_SMTP_HOST"
	envSMTPPort      = "GIBSON_SMTP_PORT"
	envSMTPUsername  = "GIBSON_SMTP_USERNAME"
	envSMTPPassword  = "GIBSON_SMTP_PASSWORD" //nolint:gosec // env var name, not a credential
	envSMTPConfigSet = "GIBSON_SMTP_CONFIGURATION_SET"

	providerLog  = "log"
	providerSMTP = "smtp"

	defaultFrom = "no-reply@gibson.local"
)

// ErrProviderUnset is returned by NewFromEnv when GIBSON_EMAIL_PROVIDER is
// empty. A missing provider must never silently select a transport that does
// not deliver: an operator who intends the dev stub sets provider=log
// explicitly, and everyone else gets a transport error they can act on.
//
// Callers must treat this as "mail is not configured" and leave the mailer
// unwired, refusing individual mail-sending RPCs — not as a boot-time fatal. A
// mail misconfiguration must not take down every other RPC.
var ErrProviderUnset = fmt.Errorf("mailer: %s is unset; set it to %q, or to %q to opt in to the non-delivering dev stub",
	envProvider, providerSMTP, providerLog)

// ErrNotDelivered is returned by LogMailer.Send. The log provider hands the
// message to nobody, so it reports failure rather than letting a caller record
// a delivery that never happened.
var ErrNotDelivered = errors.New("mailer: message not delivered (" + envProvider + "=" + providerLog + " is a non-delivering dev stub)")

// NewFromEnv builds the configured Mailer. The provider must be set explicitly:
// `smtp` requires GIBSON_SMTP_HOST, `log` selects the non-delivering dev stub,
// and an unset provider is ErrProviderUnset. Every failure mode is loud —
// nothing here silently drops mail. Callers that need real delivery, not just a
// configured transport, reject the non-delivering stub via RequireDelivering.
func NewFromEnv(logger *slog.Logger) (Mailer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	from := os.Getenv(envFrom)
	if from == "" {
		from = defaultFrom
	}
	switch provider := strings.ToLower(strings.TrimSpace(os.Getenv(envProvider))); provider {
	case "":
		return nil, ErrProviderUnset
	case providerLog:
		return &LogMailer{logger: logger, from: from}, nil
	case providerSMTP:
		host := os.Getenv(envSMTPHost)
		if host == "" {
			return nil, fmt.Errorf("mailer: %s=smtp but %s is empty", envProvider, envSMTPHost)
		}
		port := os.Getenv(envSMTPPort)
		if port == "" {
			port = "587"
		}
		return &SMTPMailer{
			from:             from,
			host:             host,
			port:             port,
			username:         os.Getenv(envSMTPUsername),
			password:         os.Getenv(envSMTPPassword),
			configurationSet: os.Getenv(envSMTPConfigSet),
		}, nil
	default:
		return nil, fmt.Errorf("mailer: unknown %s=%q (want log|smtp)", envProvider, provider)
	}
}

// LogMailer is the non-delivering dev stub, reachable only via an explicit
// GIBSON_EMAIL_PROVIDER=log. It records that a send was attempted and to whom;
// it never logs the message body. Delivers reports false, so every surface
// that depends on the recipient actually receiving the message refuses to
// start behind it (see RequireDelivering).
//
// Bodies are excluded deliberately. Verification and invitation messages carry
// single-use capability links, and the application log is a lower-trust,
// widely-shipped sink (stdout → cluster log aggregation). Writing the body
// there hands anyone with log read access a working account-takeover link.
type LogMailer struct {
	logger *slog.Logger
	from   string
}

// Send records the attempt and returns ErrNotDelivered. It always fails,
// because nothing was delivered — a caller that persists "invitation sent" or
// "verification email sent" on a nil error would be recording a lie.
func (m *LogMailer) Send(ctx context.Context, msg Message) error {
	m.logger.WarnContext(ctx, "mailer(log): message NOT delivered (non-delivering dev stub)",
		"from", m.from, "to", msg.To, "subject", msg.Subject, "body_bytes", len(msg.Text))
	return ErrNotDelivered
}

// Delivers reports false: this transport discards every message.
func (m *LogMailer) Delivers() bool { return false }
