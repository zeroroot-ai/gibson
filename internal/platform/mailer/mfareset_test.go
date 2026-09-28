// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// errMailer always fails Send, for exercising the wrapping-error branch.
type errMailer struct{ err error }

func (e *errMailer) Send(_ context.Context, _ Message) error { return e.err }
func (e *errMailer) Delivers() bool                          { return true }

func TestMFAResetSender_RendersSignInLink(t *testing.T) {
	capt := &captureMailer{}
	s := NewMFAResetSender(capt)
	err := s.SendMFAReset(context.Background(), MFAResetEmail{
		To:        "alice@example.com",
		SignInURL: "https://app.example.com/login",
	})
	if err != nil {
		t.Fatalf("SendMFAReset: %v", err)
	}
	if capt.last.To != "alice@example.com" {
		t.Errorf("To = %q", capt.last.To)
	}
	if !strings.Contains(capt.last.Text, "https://app.example.com/login") {
		t.Errorf("text body missing sign-in link: %q", capt.last.Text)
	}
	if !strings.Contains(capt.last.HTML, "https://app.example.com/login") {
		t.Errorf("html body missing sign-in link")
	}
	// SECURITY: the notice carries no code and no token — only the ordinary
	// sign-in URL. Guard against a future edit accidentally adding one.
	if strings.Contains(capt.last.Text, "code") || strings.Contains(capt.last.Text, "token") {
		t.Errorf("MFA reset notice must never carry a code or token: %q", capt.last.Text)
	}
}

func TestMFAResetSender_NoSignInURL(t *testing.T) {
	capt := &captureMailer{}
	s := NewMFAResetSender(capt)
	err := s.SendMFAReset(context.Background(), MFAResetEmail{To: "alice@example.com"})
	if err != nil {
		t.Fatalf("SendMFAReset: %v", err)
	}
	if strings.Contains(capt.last.HTML, `href=""`) {
		t.Errorf("expected no sign-in link markup when SignInURL is empty")
	}
}

func TestMFAResetSender_RequiresRecipient(t *testing.T) {
	capt := &captureMailer{}
	s := NewMFAResetSender(capt)
	if err := s.SendMFAReset(context.Background(), MFAResetEmail{}); err == nil {
		t.Fatal("expected an error for an empty recipient")
	}
}

func TestMFAResetSender_NilSender(t *testing.T) {
	var s *MFAResetSender
	if err := s.SendMFAReset(context.Background(), MFAResetEmail{To: "x"}); err == nil {
		t.Fatal("expected error from nil sender")
	}
}

func TestMFAResetSender_NilMailer(t *testing.T) {
	s := NewMFAResetSender(nil)
	if err := s.SendMFAReset(context.Background(), MFAResetEmail{To: "x"}); err == nil {
		t.Fatal("expected error from a sender with no underlying mailer")
	}
}

// TestMFAResetSender_TransportErrorIsWrapped proves a transport failure
// surfaces as a wrapped, identifiable error rather than being swallowed.
func TestMFAResetSender_TransportErrorIsWrapped(t *testing.T) {
	boom := errors.New("smtp: connection refused")
	s := NewMFAResetSender(&errMailer{err: boom})
	err := s.SendMFAReset(context.Background(), MFAResetEmail{To: "alice@example.com"})
	if err == nil {
		t.Fatal("expected the transport error to surface")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
}
