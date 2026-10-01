// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"errors"
	"html"
	"strings"
	"testing"
	"time"
)

// sampleInvitation is the fully-configured shape a Helm install produces:
// both origins set (the chart sets GIBSON_APP_URL and GIBSON_PUBLIC_URL
// unconditionally in every profile) and a tenant slug.
func sampleInvitation() InvitationEmail {
	return InvitationEmail{
		To:        "teammate@example.com",
		AcceptURL: "https://app.example.com/invite/rawtoken",
		TenantID:  "primary",
		Role:      "writer",
		ExpiresAt: time.Date(2026, 10, 8, 14, 22, 0, 0, time.UTC),
		AppURL:    "https://app.example.com",
		APIURL:    "https://api.example.com",
	}
}

// TestSendInvitation_CarriesTheWorkspacesOwnCommands is the point of the whole
// message: the tenant slug and the API origin are the two values an invitee
// cannot guess, and the daemon is the one component that knows both. If they
// are missing the email has taught nobody anything.
func TestSendInvitation_CarriesTheWorkspacesOwnCommands(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if len(capture.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(capture.sent))
	}
	m := capture.sent[0]
	for _, want := range []string{
		"gibson init --gibson-url https://api.example.com",
		"gibson login --tenant primary",
		"https://app.example.com/invite/rawtoken",
		"git clone " + adkCloneURL,
		"gibson mission submit mission.cue",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("text part is missing %q", want)
		}
		if !strings.Contains(m.HTML, html.EscapeString(want)) {
			t.Errorf("HTML part is missing %q", want)
		}
	}
}

// TestSendInvitation_NoSecondEmailIsPromised — the defect this rewrite exists
// to fix. Zitadel mints the setup code with returnCode, never sendCode
// (idp.AdminClient.CreateSetupLink), so the identity service sends nothing.
// Telling the invitee to wait for a second email left them unable to set a
// password at all.
func TestSendInvitation_NoSecondEmailIsPromised(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	body := strings.ToLower(capture.sent[0].Text + capture.sent[0].HTML)
	for _, forbidden := range []string{
		"second email",
		"identity service",
		"check your email",
		"another email",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("body promises a message nothing sends: %q", forbidden)
		}
	}
}

// TestSendInvitation_GreetsWithoutAName: the daemon has no name for an invitee
// at invite time — only an address — so the greeting must never interpolate
// one or leave a placeholder behind.
func TestSendInvitation_GreetsWithoutAName(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	m := capture.sent[0]
	if !strings.HasPrefix(m.Text, "Hello,\n") {
		t.Errorf("text part should open with a bare \"Hello,\", got: %.20q", m.Text)
	}
	for _, placeholder := range []string{"$name", "{name}", "%s,", "[NAME]", "Hi "} {
		if strings.Contains(m.Text, placeholder) || strings.Contains(m.HTML, placeholder) {
			t.Errorf("body carries the placeholder %q", placeholder)
		}
	}
}

// TestSendInvitation_CommandsPasteWithoutEditing: a command block is meant to
// be selected and pasted whole, so no line may carry a shell prompt and no
// line may carry an unfilled placeholder. A `$` inside a line is fine
// ($PWD/$PATH); a leading one is a prompt.
func TestSendInvitation_CommandsPasteWithoutEditing(t *testing.T) {
	for _, st := range invitationSteps(sampleInvitation()) {
		for _, c := range st.Cmds {
			if strings.HasPrefix(c, "$") || strings.HasPrefix(c, "> ") {
				t.Errorf("step %q: command line carries a prompt: %q", st.Title, c)
			}
			if strings.HasPrefix(c, "#") {
				continue
			}
			if strings.ContainsAny(c, "<>") {
				t.Errorf("step %q: command line carries a placeholder the reader must fill in: %q", st.Title, c)
			}
		}
	}
}

// TestSendInvitation_NoDeadDocsLink: the old body pointed at
// https://docs.zeroroot.ai/docs/invited, which 404ed and is now deleted. No
// link in this email may point at a page that does not exist, and the two
// origins it is handed are the only hosts it has any business naming.
func TestSendInvitation_NoDeadDocsLink(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	body := capture.sent[0].Text + capture.sent[0].HTML
	for _, dead := range []string{"docs.zeroroot.ai", "/docs/invited"} {
		if strings.Contains(body, dead) {
			t.Errorf("body links %q, which does not exist", dead)
		}
	}
}

// TestSendInvitation_OneBodyForEveryRole: the role changes the label a person
// reads and nothing else. A per-role body is a second thing to keep true, and
// the submit-needs-Editor line keeps the single body honest for a Viewer.
func TestSendInvitation_OneBodyForEveryRole(t *testing.T) {
	base := sampleInvitation()
	shapes := map[string]string{}
	for _, role := range []string{"owner", "admin", "writer", "member", "nonsense"} {
		inv := base
		inv.Role = role
		var cmds []string
		for _, st := range invitationSteps(inv) {
			cmds = append(cmds, st.Title)
			cmds = append(cmds, st.Cmds...)
		}
		shapes[role] = strings.Join(cmds, "\n")
	}
	want := shapes["writer"]
	for role, got := range shapes {
		if got != want {
			t.Errorf("role %q renders a different runbook than writer", role)
		}
	}
	capture := &verifyCaptureMailer{}
	viewer := base
	viewer.Role = "member"
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), viewer); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if !strings.Contains(capture.sent[0].Text, "needs the Editor role") {
		t.Error("a Viewer must be told why submit will refuse; the single body relies on that line")
	}
	if !strings.Contains(capture.sent[0].Text, "a Viewer") {
		t.Error("the role label a person reads is missing")
	}
}

// TestSendInvitation_WithoutAnAPIOriginDegrades: a daemon run by hand, with no
// chart to set GIBSON_PUBLIC_URL, must still send a usable invitation. The CLI
// steps are replaced by the one page that can fill them in — never by a
// half-written command.
func TestSendInvitation_WithoutAnAPIOriginDegrades(t *testing.T) {
	inv := sampleInvitation()
	inv.APIURL = ""
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), inv); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	m := capture.sent[0]
	if !strings.Contains(m.Text, "https://app.example.com/dashboard/pages/settings/cli") {
		t.Error("with no API origin the email must point at Settings → CLI")
	}
	if strings.Contains(m.Text, "--gibson-url") {
		t.Error("a --gibson-url command with no URL to put in it must not be rendered")
	}
	if !strings.Contains(m.Text, inv.AcceptURL) {
		t.Error("the accept link is the one thing that must survive every degraded mode")
	}
}

// TestSendInvitation_HTMLIsMailClientSafe: the HTML part renders in Gmail and
// Outlook, not a 2026 browser. Table layout, inline styles, hex colors. A
// stylesheet link (Gmail strips it), a flex/grid layout, or an oklch() color
// silently degrades to unstyled text for most recipients.
func TestSendInvitation_HTMLIsMailClientSafe(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	got := capture.sent[0].HTML
	for _, forbidden := range []string{"<link", "oklch(", "display:flex", "display:grid", "var(--", "@media"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("HTML part carries %q, which mail clients do not render", forbidden)
		}
	}
	if !strings.Contains(got, `role="presentation"`) {
		t.Error("HTML part should lay out with presentation tables")
	}
	if !strings.Contains(got, cTermBg) {
		t.Error("the terminal panel background is missing; the commands lost their prompt box")
	}
}

// TestSendInvitation_EscapesTheCommandsItPrints: `export PATH="$PWD/..."`
// carries quotes, and an unescaped one ends the enclosing attribute.
func TestSendInvitation_EscapesTheCommandsItPrints(t *testing.T) {
	capture := &verifyCaptureMailer{}
	if err := NewInvitationSender(capture).SendInvitation(context.Background(), sampleInvitation()); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	got := capture.sent[0].HTML
	if !strings.Contains(got, `export PATH=&#34;$PWD/gibson/bin:$PATH&#34;`) {
		t.Error("the PATH export is not HTML-escaped; a raw quote breaks the enclosing element")
	}
	if strings.Contains(got, `export PATH="$PWD`) {
		t.Error("a raw double quote reached the HTML part")
	}
}

// TestRoleLabel_NamesRolesNotRelations: the daemon speaks relations, a person
// reads role names (ADR-0093 decision 2). This email is the only surface
// outside the dashboard that puts a role in front of a person.
func TestRoleLabel_NamesRolesNotRelations(t *testing.T) {
	for relation, want := range map[string]string{
		"owner":  "the Owner",
		"admin":  "an Admin",
		"writer": "an Editor",
		"member": "a Viewer",
		"":       "a Viewer",
	} {
		if got := roleLabel(relation); got != want {
			t.Errorf("roleLabel(%q) = %q, want %q", relation, got, want)
		}
	}
}

// TestExpiryLabel_FallsBackWhenZero: an unset deadline must not render as
// "on 1 January 0001".
func TestExpiryLabel_FallsBackWhenZero(t *testing.T) {
	if got := expiryLabel(time.Time{}); got != "in seven days" {
		t.Errorf("expiryLabel(zero) = %q, want the relative fallback", got)
	}
	if got := expiryLabel(time.Date(2026, 10, 8, 14, 22, 0, 0, time.UTC)); !strings.Contains(got, "8 October 2026") {
		t.Errorf("expiryLabel = %q, want the absolute UTC deadline", got)
	}
}

// TestSendInvitation_UnconfiguredSenderRefuses mirrors the conflict notice's
// own nil-sender guard.
func TestSendInvitation_UnconfiguredSenderRefuses(t *testing.T) {
	var s *InvitationSender
	if err := s.SendInvitation(context.Background(), sampleInvitation()); err == nil {
		t.Error("expected an error from an unconfigured sender")
	}
}

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
	// Matched on the remedy, not on one phrasing of it: the copy says "a
	// different address" now, and a test pinned to the older "different email
	// address" fails a wording change that kept both remedies intact.
	if !strings.Contains(strings.ToLower(m.Text), "different address") ||
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
