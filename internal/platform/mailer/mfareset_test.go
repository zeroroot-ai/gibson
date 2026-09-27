// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"strings"
	"testing"
)

func TestMFAResetSender_RendersSignInLink(t *testing.T) {
	cap := &captureMailer{}
	s := NewMFAResetSender(cap)
	err := s.SendMFAReset(context.Background(), MFAResetEmail{
		To:        "alice@example.com",
		SignInURL: "https://app.example.com/login",
	})
	if err != nil {
		t.Fatalf("SendMFAReset: %v", err)
	}
	if cap.last.To != "alice@example.com" {
		t.Errorf("To = %q", cap.last.To)
	}
	if !strings.Contains(cap.last.Text, "https://app.example.com/login") {
		t.Errorf("text body missing sign-in link: %q", cap.last.Text)
	}
	if !strings.Contains(cap.last.HTML, "https://app.example.com/login") {
		t.Errorf("html body missing sign-in link")
	}
	// SECURITY: the notice carries no code and no token — only the ordinary
	// sign-in URL. Guard against a future edit accidentally adding one.
	if strings.Contains(cap.last.Text, "code") || strings.Contains(cap.last.Text, "token") {
		t.Errorf("MFA reset notice must never carry a code or token: %q", cap.last.Text)
	}
}

func TestMFAResetSender_NoSignInURL(t *testing.T) {
	cap := &captureMailer{}
	s := NewMFAResetSender(cap)
	err := s.SendMFAReset(context.Background(), MFAResetEmail{To: "alice@example.com"})
	if err != nil {
		t.Fatalf("SendMFAReset: %v", err)
	}
	if strings.Contains(cap.last.HTML, `href=""`) {
		t.Errorf("expected no sign-in link markup when SignInURL is empty")
	}
}

func TestMFAResetSender_RequiresRecipient(t *testing.T) {
	cap := &captureMailer{}
	s := NewMFAResetSender(cap)
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
