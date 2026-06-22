// Package mailer is a vendor-neutral transactional-email sender for the daemon.
//
// gibson#632: MembershipService.InviteMember / ResendInvitation send the
// invitation accept-link email from the daemon (the invitation lifecycle moved
// off the tenant-operator saga in gibson#626). All daemon code that needs to
// send mail programs against the Mailer interface; concrete transports
// (SMTP, log) live behind NewFromEnv.
//
// The provider is selected at construction from the environment so dev/kind
// clusters run with the "log" provider (no SMTP dependency) while production
// sets provider=smtp.
package mailer

import (
	"context"
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
}

// Env var names. The provider gates which transport NewFromEnv builds.
const (
	envProvider     = "GIBSON_EMAIL_PROVIDER" // "log" (default) | "smtp"
	envFrom         = "GIBSON_EMAIL_FROM"
	envSMTPHost     = "GIBSON_SMTP_HOST"
	envSMTPPort     = "GIBSON_SMTP_PORT"
	envSMTPUsername = "GIBSON_SMTP_USERNAME"
	envSMTPPassword = "GIBSON_SMTP_PASSWORD" //nolint:gosec // env var name, not a credential

	providerLog  = "log"
	providerSMTP = "smtp"

	defaultFrom = "no-reply@gibson.local"
)

// NewFromEnv builds the configured Mailer. Unset/`log` provider yields a
// LogMailer (dev default). `smtp` requires GIBSON_SMTP_HOST; missing host is a
// configuration error (fail loud rather than silently dropping mail).
func NewFromEnv(logger *slog.Logger) (Mailer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	from := os.Getenv(envFrom)
	if from == "" {
		from = defaultFrom
	}
	switch provider := strings.ToLower(strings.TrimSpace(os.Getenv(envProvider))); provider {
	case "", providerLog:
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
			from:     from,
			host:     host,
			port:     port,
			username: os.Getenv(envSMTPUsername),
			password: os.Getenv(envSMTPPassword),
		}, nil
	default:
		return nil, fmt.Errorf("mailer: unknown %s=%q (want log|smtp)", envProvider, provider)
	}
}

// LogMailer logs the message instead of sending it. It is the dev/kind default
// — the accept link is logged at INFO so a developer can click it.
type LogMailer struct {
	logger *slog.Logger
	from   string
}

// Send logs the message. Never fails.
func (m *LogMailer) Send(ctx context.Context, msg Message) error {
	m.logger.InfoContext(ctx, "mailer(log): email not sent (log provider)",
		"from", m.from, "to", msg.To, "subject", msg.Subject, "body", msg.Text)
	return nil
}
