package mailer

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewFromEnv_DefaultsToLog(t *testing.T) {
	t.Setenv(envProvider, "")
	m, err := NewFromEnv(nil)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if _, ok := m.(*LogMailer); !ok {
		t.Fatalf("default provider = %T, want *LogMailer", m)
	}
}

func TestNewFromEnv_SMTPRequiresHost(t *testing.T) {
	t.Setenv(envProvider, "smtp")
	t.Setenv(envSMTPHost, "")
	if _, err := NewFromEnv(nil); err == nil {
		t.Fatal("expected error when provider=smtp and host empty")
	}
}

func TestNewFromEnv_SMTPBuildsMailer(t *testing.T) {
	t.Setenv(envProvider, "smtp")
	t.Setenv(envSMTPHost, "smtp.example.com")
	t.Setenv(envSMTPPort, "")
	m, err := NewFromEnv(nil)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	sm, ok := m.(*SMTPMailer)
	if !ok {
		t.Fatalf("provider=smtp → %T, want *SMTPMailer", m)
	}
	if sm.port != "587" {
		t.Errorf("default port = %q, want 587", sm.port)
	}
}

func TestNewFromEnv_UnknownProvider(t *testing.T) {
	t.Setenv(envProvider, "carrier-pigeon")
	if _, err := NewFromEnv(nil); err == nil {
		t.Fatal("expected error on unknown provider")
	}
}

// captureMailer records the last message for assertions.
type captureMailer struct{ last Message }

func (c *captureMailer) Send(_ context.Context, msg Message) error { c.last = msg; return nil }

func TestInvitationSender_RendersAcceptLink(t *testing.T) {
	cap := &captureMailer{}
	s := NewInvitationSender(cap)
	exp := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	err := s.SendInvitation(context.Background(), InvitationEmail{
		To:        "bob@example.com",
		AcceptURL: "https://app.example.com/invite/tok123",
		Role:      "admin",
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if cap.last.To != "bob@example.com" {
		t.Errorf("To = %q", cap.last.To)
	}
	if !strings.Contains(cap.last.Text, "https://app.example.com/invite/tok123") {
		t.Errorf("text body missing accept link: %q", cap.last.Text)
	}
	if !strings.Contains(cap.last.HTML, "https://app.example.com/invite/tok123") {
		t.Errorf("html body missing accept link")
	}
	if !strings.Contains(cap.last.Text, "an admin") {
		t.Errorf("text body missing role label: %q", cap.last.Text)
	}
}

func TestInvitationSender_NilMailer(t *testing.T) {
	var s *InvitationSender
	if err := s.SendInvitation(context.Background(), InvitationEmail{To: "x"}); err == nil {
		t.Fatal("expected error from nil sender")
	}
}

func TestSMTPMailer_BuildRFC822_Multipart(t *testing.T) {
	m := &SMTPMailer{from: "no-reply@gibson.local"}
	raw := string(m.buildRFC822(Message{To: "a@b.com", Subject: "Hi", Text: "plain", HTML: "<p>rich</p>"}))
	for _, want := range []string{
		"From: no-reply@gibson.local\r\n",
		"To: a@b.com\r\n",
		"Subject: Hi\r\n",
		"multipart/alternative",
		"text/plain",
		"text/html",
		"<p>rich</p>",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("RFC822 missing %q in:\n%s", want, raw)
		}
	}
}
