// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mail

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// The regression these cover, in full: gibson#561 replaced `smtp.SendMail` with
// two modes that both encrypt. `UseTLS=false` had NOT meant STARTTLS — it meant
// `smtp.SendMail`, which upgrades only when the server advertises it, so against
// a sink with no STARTTLS it sent in the clear and worked.
//
// Three hosted overlays depend on exactly that: test/signup, test/identity and
// test/platform-owner point the tenant operator at `gibson-mailpit:1025`, which
// has no certificate. After the two-mode enum no value could reach them, so
// those exit tests could not deliver mail at all. TLSModePlaintext is that path,
// named rather than inferred.

// mailpitListener stands in for an in-cluster Mailpit on 1025: it greets, offers
// NO STARTTLS, and accepts a whole message. The shape the two-mode enum could
// not talk to.
func mailpitListener(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				_, _ = c.Write([]byte("220 mailpit.example.test ESMTP\r\n"))
				inData := false
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if inData {
						if strings.TrimRight(line, "\r\n") == "." {
							inData = false
							_, _ = c.Write([]byte("250 2.0.0 Ok: queued\r\n"))
						}
						continue
					}
					up := strings.ToUpper(strings.TrimRight(line, "\r\n"))
					switch {
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
						// No STARTTLS, and no AUTH: an anonymous sink.
						_, _ = c.Write([]byte("250-mailpit.example.test\r\n250 SIZE 10240000\r\n"))
					case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
						_, _ = c.Write([]byte("250 2.1.0 Ok\r\n"))
					case strings.HasPrefix(up, "DATA"):
						inData = true
						_, _ = c.Write([]byte("354 End data with <CR><LF>.<CR><LF>\r\n"))
					case strings.HasPrefix(up, "QUIT"):
						_, _ = c.Write([]byte("221 2.0.0 Bye\r\n"))
						return
					default:
						_, _ = c.Write([]byte("250 2.0.0 Ok\r\n"))
					}
				}
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestSend_PlaintextToASinkWithNoSTARTTLS_Delivers is THE regression test. Run
// it against the two-mode enum and there is no mode to pass: this is the case
// that had no spelling.
func TestSend_PlaintextToASinkWithNoSTARTTLS_Delivers(t *testing.T) {
	host, port := mailpitListener(t)
	s, err := NewSMTPSender(testConfig(TLSModePlaintext, host, port))
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if err := s.SendInvitation(context.Background(), InvitationMessage{
		To:           "owner@example.test",
		TenantName:   "acme",
		InviterEmail: "owner@acme.test",
		AcceptURL:    "https://example.test/accept?code=abc",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("plaintext send to a sink with no STARTTLS: %v", err)
	}
}

// And the other half of the same fact: STARTTLS against that same sink still
// fails. The regression was never that mandatory STARTTLS is wrong — it is
// right, and TestSend_ServerWithoutSTARTTLS_NamesTheUpgrade keeps pinning it.
// The regression was that there was no other mode to choose.
func TestSend_STARTTLSToTheSameSink_StillFails(t *testing.T) {
	host, port := mailpitListener(t)
	s, err := NewSMTPSender(testConfig(TLSModeSTARTTLS, host, port))
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	err = s.SendInvitation(context.Background(), InvitationMessage{To: "owner@example.test"})
	if err == nil {
		t.Fatal("STARTTLS succeeded against a sink that does not offer it")
	}
	if !strings.Contains(err.Error(), "starttls") {
		t.Errorf("the error does not name the upgrade that failed: %v", err)
	}
	// And it must now point at BOTH other modes, not one. With two modes a
	// binary flip was right; with three, naming one is a coin toss.
	for _, want := range []string{string(TLSModeImplicit), string(TLSModePlaintext)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not offer %q as an alternative: %v", want, err)
		}
	}
}

// A credential over an unencrypted link is the one thing this mode must not
// allow. net/smtp refuses it at send time; refusing at construction says which
// two settings conflict while the operator is still looking at the config.
func TestNewSMTPSender_RefusesPlaintextWithAUsername(t *testing.T) {
	cfg := testConfig(TLSModePlaintext, "mail.example.test", 1025)
	cfg.Username = "apikey"
	cfg.Password = "s3cret"

	_, err := NewSMTPSender(cfg)
	if err == nil {
		t.Fatal("plaintext with a username was accepted; the password would go out in the clear")
	}
	for _, want := range []string{
		string(TLSModePlaintext), // the mode at fault
		"apikey",                 // which credential
		"mail.example.test:1025", // where it would have gone
		string(TLSModeSTARTTLS),  // what to do instead
		string(TLSModeImplicit),  //
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// The password itself must never appear in an error that gets logged.
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("the refusal leaks the password: %v", err)
	}
}

// An anonymous sink needs no credential, and that is the shape the three hosted
// overlays declare. It constructs.
func TestNewSMTPSender_AcceptsPlaintextWithoutACredential(t *testing.T) {
	if _, err := NewSMTPSender(testConfig(TLSModePlaintext, "gibson-mailpit", 1025)); err != nil {
		t.Fatalf("plaintext with no credential: %v", err)
	}
}

// The default is never plaintext. Not encrypting is a choice an operator makes
// explicitly, so an absent SMTP_TLS_MODE must still mean STARTTLS.
func TestNewSMTPSender_EmptyModeIsNeverPlaintext(t *testing.T) {
	s, err := NewSMTPSender(testConfig("", "mail.example.test", 587))
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if s.cfg.TLSMode != TLSModeSTARTTLS {
		t.Errorf("empty mode resolved to %q, want %q", s.cfg.TLSMode, TLSModeSTARTTLS)
	}
}

// The unknown-mode refusal has to list all three, or an operator who typed
// "none" or "off" learns two of their options and not the one they wanted.
func TestNewSMTPSender_UnknownModeNamesAllThree(t *testing.T) {
	_, err := NewSMTPSender(testConfig("none", "mail.example.test", 1025))
	if err == nil {
		t.Fatal(`"none" was accepted; it is not a mode`)
	}
	for _, want := range []TLSMode{TLSModeSTARTTLS, TLSModeImplicit, TLSModePlaintext} {
		if !strings.Contains(err.Error(), string(want)) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}
