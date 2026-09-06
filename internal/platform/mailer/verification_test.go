// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type verifyCaptureMailer struct {
	sent []Message
	err  error
}

func (c *verifyCaptureMailer) Send(_ context.Context, m Message) error {
	if c.err != nil {
		return c.err
	}
	c.sent = append(c.sent, m)
	return nil
}

func (c *verifyCaptureMailer) Delivers() bool { return true }

// TestSendSignupVerification_CarriesTheLink — the link is the whole payload;
// a message without it is a dead end for the recipient.
func TestSendSignupVerification_CarriesTheLink(t *testing.T) {
	capture := &verifyCaptureMailer{}
	s := NewVerificationSender(capture)

	err := s.SendSignupVerification(context.Background(), VerificationEmail{
		To:             "owner@example.com",
		ContinueURL:    "https://app.example.test/signup/verify?token=abc123",
		ExpiresInHours: 24,
	})
	if err != nil {
		t.Fatalf("SendSignupVerification: %v", err)
	}
	if len(capture.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(capture.sent))
	}
	m := capture.sent[0]
	if m.To != "owner@example.com" {
		t.Errorf("To = %q", m.To)
	}
	if !strings.Contains(m.Text, "https://app.example.test/signup/verify?token=abc123") {
		t.Errorf("the text body is missing the continue link:\n%s", m.Text)
	}
	if !strings.Contains(m.HTML, "token=abc123") {
		t.Errorf("the HTML body is missing the continue link")
	}
	if !strings.Contains(m.Text, "24 hours") {
		t.Errorf("the body should state the expiry, got:\n%s", m.Text)
	}
}

// TestSendAccountExists_CarriesNoToken is the property that keeps the
// duplicate-address notice from becoming a takeover vector: it tells the owner
// what happened and gives them nothing that could complete a signup.
func TestSendAccountExists_CarriesNoToken(t *testing.T) {
	capture := &verifyCaptureMailer{}
	s := NewVerificationSender(capture)

	err := s.SendAccountExists(context.Background(), AccountExistsEmail{
		To:            "owner@example.com",
		SignInURL:     "https://app.example.test/login",
		PasswordReset: "https://app.example.test/login?prompt=reset",
	})
	if err != nil {
		t.Fatalf("SendAccountExists: %v", err)
	}
	m := capture.sent[0]
	for _, forbidden := range []string{"token=", "/signup/verify", "/signup/continue"} {
		if strings.Contains(m.Text, forbidden) || strings.Contains(m.HTML, forbidden) {
			t.Errorf("the account-exists notice carries %q; it must contain no continuation capability", forbidden)
		}
	}
	if !strings.Contains(m.Text, "https://app.example.test/login") {
		t.Errorf("the notice should point the owner at sign-in")
	}
	// It must also be honest about the non-event: nothing changed.
	if !strings.Contains(strings.ToLower(m.Text), "no new account was created") {
		t.Errorf("the notice should say that nothing was created, got:\n%s", m.Text)
	}
}

// TestSendAccountExists_RequiresRecipient — a configured sender with no
// address to write to must refuse rather than build a message for nobody.
func TestSendAccountExists_RequiresRecipient(t *testing.T) {
	s := NewVerificationSender(&verifyCaptureMailer{})
	if err := s.SendAccountExists(context.Background(), AccountExistsEmail{}); err == nil {
		t.Error("expected an error when the recipient is empty")
	}
}

// TestSendSignupVerification_SingularHourWording — the expiry line must read
// naturally at exactly one hour, not "1 hours".
func TestSendSignupVerification_SingularHourWording(t *testing.T) {
	capture := &verifyCaptureMailer{}
	s := NewVerificationSender(capture)

	err := s.SendSignupVerification(context.Background(), VerificationEmail{
		To:             "owner@example.com",
		ContinueURL:    "https://app.example.test/signup/verify?token=abc123",
		ExpiresInHours: 1,
	})
	if err != nil {
		t.Fatalf("SendSignupVerification: %v", err)
	}
	if !strings.Contains(capture.sent[0].Text, "1 hour.") {
		t.Errorf("expected singular wording for a 1-hour expiry, got:\n%s", capture.sent[0].Text)
	}
}

// TestVerificationSender_RequiresConfiguration — a nil transport must be an
// error the handler can act on, not a silently dropped message. The signup
// handler turns this into a refusal rather than a false "check your inbox".
func TestVerificationSender_RequiresConfiguration(t *testing.T) {
	var s *VerificationSender
	if err := s.SendSignupVerification(context.Background(), VerificationEmail{To: "a@b.c", ContinueURL: "u"}); err == nil {
		t.Errorf("expected an error from an unconfigured sender")
	}
	empty := NewVerificationSender(nil)
	if err := empty.SendAccountExists(context.Background(), AccountExistsEmail{To: "a@b.c"}); err == nil {
		t.Errorf("expected an error from a sender with no transport")
	}
	configured := NewVerificationSender(&verifyCaptureMailer{})
	if err := configured.SendSignupVerification(context.Background(), VerificationEmail{To: "a@b.c"}); err == nil {
		t.Errorf("expected an error when the continue URL is missing")
	}
}

// TestSendSignupVerification_WrapsTransportError — a send failure must be
// fatal and inspectable, not swallowed. The signup handler distinguishes a
// broken transport from every other refusal by unwrapping this error.
func TestSendSignupVerification_WrapsTransportError(t *testing.T) {
	transportErr := errors.New("smtp: connection refused")
	capture := &verifyCaptureMailer{err: transportErr}
	s := NewVerificationSender(capture)

	err := s.SendSignupVerification(context.Background(), VerificationEmail{
		To:          "owner@example.com",
		ContinueURL: "https://app.example.test/signup/verify?token=abc123",
	})
	if err == nil {
		t.Fatal("expected an error when the transport fails")
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("error does not wrap the transport failure: %v", err)
	}
}

// TestSendAccountExists_WrapsTransportError — same property on the
// duplicate-address path: a delivery failure here must not read as success.
func TestSendAccountExists_WrapsTransportError(t *testing.T) {
	transportErr := errors.New("smtp: connection refused")
	capture := &verifyCaptureMailer{err: transportErr}
	s := NewVerificationSender(capture)

	err := s.SendAccountExists(context.Background(), AccountExistsEmail{To: "owner@example.com"})
	if err == nil {
		t.Fatal("expected an error when the transport fails")
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("error does not wrap the transport failure: %v", err)
	}
}

// TestSMTPConfigurationSetHeader — SES routes bounce and complaint events by
// this header. Without it those events are invisible, and for a flow whose only
// proof of identity is an email, silent delivery failure is a total outage.
func TestSMTPConfigurationSetHeader(t *testing.T) {
	with := &SMTPMailer{from: "no-reply@example.test", configurationSet: "gibson-transactional-prod"}
	got := string(with.buildRFC822(Message{To: "a@b.c", Subject: "s", Text: "t"}))
	if !strings.Contains(got, "X-SES-CONFIGURATION-SET: gibson-transactional-prod\r\n") {
		t.Errorf("the configuration-set header is missing:\n%s", got)
	}

	without := &SMTPMailer{from: "no-reply@example.test"}
	got = string(without.buildRFC822(Message{To: "a@b.c", Subject: "s", Text: "t"}))
	if strings.Contains(got, "X-SES-CONFIGURATION-SET") {
		t.Errorf("an unset configuration set should emit no header:\n%s", got)
	}
}
