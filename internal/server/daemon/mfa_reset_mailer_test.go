// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// mfa_reset_mailer_test.go mirrors signup_mailer_test.go: resolveMFAResetMailer
// never fails the daemon's own startup on a mail misconfiguration; it warns
// and leaves the sender unwired, which is what makes ResetUserMFA's
// notified=false response field meaningful (hosted#206).

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestResolveMFAResetMailer_NoProviderConfigured(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "")

	var buf bytes.Buffer
	sender := resolveMFAResetMailer(context.Background(), bufferLogger(&buf))

	if sender != nil {
		t.Errorf("sender = %v, want nil when no provider is configured", sender)
	}
	out := buf.String()
	if !strings.Contains(out, "WARN") {
		t.Errorf("expected a WARN log line, got:\n%s", out)
	}
	if !strings.Contains(out, "ResetUserMFA") {
		t.Errorf("warning does not name the affected RPC:\n%s", out)
	}
}

func TestResolveMFAResetMailer_LogProviderIsNotDelivering(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "log")

	var buf bytes.Buffer
	sender := resolveMFAResetMailer(context.Background(), bufferLogger(&buf))
	if sender != nil {
		t.Errorf("sender = %v, want nil: the log provider must never be selected implicitly as a delivering transport", sender)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Errorf("expected a WARN log line, got:\n%s", buf.String())
	}
}

func TestResolveMFAResetMailer_DeliveringTransportIsWired(t *testing.T) {
	t.Setenv("GIBSON_EMAIL_PROVIDER", "smtp")
	t.Setenv("GIBSON_SMTP_HOST", "smtp.example.test")

	var buf bytes.Buffer
	sender := resolveMFAResetMailer(context.Background(), bufferLogger(&buf))
	if sender == nil {
		t.Fatal("sender = nil, want a wired MFAResetSender when SMTP is configured")
	}
	if buf.Len() != 0 {
		t.Errorf("a correctly configured transport should not warn: %s", buf.String())
	}
}
