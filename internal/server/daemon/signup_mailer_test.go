// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// signup_mailer_test.go proves the mail-transport wiring for self-serve
// signup can no longer stop the daemon from booting (gibson#1228 / PR #1228):
// resolveSignupMailer never returns an error, in either the self-serve or
// admin-only profile, and it warns instead of failing when no delivering
// transport is configured.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

func bufferLogger(buf *bytes.Buffer) *observability.Logger {
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return observability.NewLoggerFromSlog(slog.New(handler), observability.Config{})
}

// TestResolveSignupMailer_NoProviderConfigured proves the daemon does not
// fail to construct its mailer when GIBSON_EMAIL_PROVIDER is unset — the
// central regression this change fixes. Before this change the equivalent
// code path in buildGRPCServer returned a fatal error when SIGNUP_SELF_SERVE
// was set; resolveSignupMailer has no error return at all, so a caller
// cannot propagate one even by accident.
func TestResolveSignupMailer_NoProviderConfigured(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "")

	for _, selfServe := range []bool{true, false} {
		var buf bytes.Buffer
		sender := resolveSignupMailer(context.Background(), bufferLogger(&buf), selfServe)

		if sender != nil {
			t.Errorf("selfServe=%v: sender = %v, want nil when no provider is configured", selfServe, sender)
		}

		out := buf.String()
		if !strings.Contains(out, "WARN") {
			t.Errorf("selfServe=%v: expected a WARN log line, got:\n%s", selfServe, out)
		}
		if !strings.Contains(out, "no delivering mail transport") {
			t.Errorf("selfServe=%v: warning does not name the problem:\n%s", selfServe, out)
		}
	}
}

// TestResolveSignupMailer_LogProviderIsNotDelivering proves that explicitly
// selecting the log provider is treated the same as no provider at all: it
// does not deliver, so it is refused the same way, never fatally.
func TestResolveSignupMailer_LogProviderIsNotDelivering(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "log")

	var buf bytes.Buffer
	sender := resolveSignupMailer(context.Background(), bufferLogger(&buf), true)
	if sender != nil {
		t.Errorf("sender = %v, want nil: the log provider must never be selected implicitly as a delivering transport", sender)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Errorf("expected a WARN log line, got:\n%s", buf.String())
	}
}

// TestResolveSignupMailer_SelfServeWarningIsActionable proves the self-serve
// warning names the operator-facing effect (RPCs will refuse) and the fix
// (which env vars to set), not just the underlying error.
func TestResolveSignupMailer_SelfServeWarningIsActionable(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "")

	var buf bytes.Buffer
	resolveSignupMailer(context.Background(), bufferLogger(&buf), true)

	out := buf.String()
	for _, want := range []string{"FailedPrecondition", "GIBSON_EMAIL_PROVIDER", "GIBSON_SMTP_HOST"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q; an operator needs this to fix the deployment:\n%s", want, out)
		}
	}
}

// TestResolveSignupMailer_DeliveringTransportIsWired proves the happy path:
// a valid SMTP configuration produces a usable sender and logs nothing.
func TestResolveSignupMailer_DeliveringTransportIsWired(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "smtp")
	t.Setenv("GIBSON_SMTP_HOST", "smtp.example.test")

	var buf bytes.Buffer
	sender := resolveSignupMailer(context.Background(), bufferLogger(&buf), true)
	if sender == nil {
		t.Fatal("sender = nil, want a wired VerificationSender when SMTP is configured")
	}
	if buf.Len() != 0 {
		t.Errorf("a correctly configured transport should not warn: %s", buf.String())
	}
}
