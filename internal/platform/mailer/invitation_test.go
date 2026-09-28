// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestSendInvitationConflict_TellsTheInviteeOnly — hosted#203: the notice
// goes to the address (the mailbox that owns it), never back to whoever sent
// the invitation, and it names both remedies the issue text promises.
func TestSendInvitationConflict_TellsTheInviteeOnly(t *testing.T) {
	capture := &verifyCaptureMailer{}
	s := NewInvitationSender(capture)

	err := s.SendInvitationConflict(context.Background(), InvitationConflictEmail{To: "taken@example.com"})
	if err != nil {
		t.Fatalf("SendInvitationConflict: %v", err)
	}
	if len(capture.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(capture.sent))
	}
	m := capture.sent[0]
	if m.To != "taken@example.com" {
		t.Errorf("To = %q, want the invitee's own address", m.To)
	}
	if !strings.Contains(m.Text, "taken@example.com") {
		t.Errorf("body should name the address, got:\n%s", m.Text)
	}
	if !strings.Contains(strings.ToLower(m.Text), "different email address") ||
		!strings.Contains(strings.ToLower(m.Text), "owner") {
		t.Errorf("body should offer both remedies (a different address, or the Owner removing them), got:\n%s", m.Text)
	}
	// No accept link and no invitation-specific token: there is nothing to
	// accept, this is a notice, not an invitation.
	for _, forbidden := range []string{"/invite/", "token="} {
		if strings.Contains(m.Text, forbidden) || strings.Contains(m.HTML, forbidden) {
			t.Errorf("the conflict notice carries %q; it must carry no accept capability", forbidden)
		}
	}
}

// TestSendInvitationConflict_UnconfiguredSenderRefuses mirrors
// SendInvitation's own nil-sender guard.
func TestSendInvitationConflict_UnconfiguredSenderRefuses(t *testing.T) {
	var s *InvitationSender
	if err := s.SendInvitationConflict(context.Background(), InvitationConflictEmail{To: "a@b.com"}); err == nil {
		t.Error("expected an error from an unconfigured sender")
	}
}

// TestSendInvitationConflict_WrapsTransportError: a transport failure must
// be surfaced, not swallowed.
func TestSendInvitationConflict_WrapsTransportError(t *testing.T) {
	transportErr := errors.New("smtp: connection refused")
	capture := &verifyCaptureMailer{err: transportErr}
	s := NewInvitationSender(capture)

	err := s.SendInvitationConflict(context.Background(), InvitationConflictEmail{To: "taken@example.com"})
	if err == nil {
		t.Fatal("expected a wrapped transport error")
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("error does not wrap the transport failure: %v", err)
	}
}
