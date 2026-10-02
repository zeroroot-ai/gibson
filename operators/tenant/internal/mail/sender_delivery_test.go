// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP speaks enough SMTP to accept one message, in either TLS mode. It
// exists because nothing tested that a mail is actually delivered — only that a
// mismatch fails — so every line of the envelope exchange was uncovered, and a
// dropped step would have passed review.
type fakeSMTP struct {
	t    *testing.T
	cert tls.Certificate

	mu       sync.Mutex
	received []string // the DATA body of each accepted message
	authSeen bool
}

// serve runs the protocol on one connection. `upgradable` means the connection
// starts in plaintext and STARTTLS is offered; otherwise it is already TLS.
func (f *fakeSMTP) serve(conn net.Conn, upgradable bool) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	say := func(s string) {
		_, _ = rw.WriteString(s + "\r\n")
		_ = rw.Flush()
	}

	say("220 fake.example.test ESMTP")
	var body strings.Builder
	inData := false

	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.received = append(f.received, body.String())
				f.mu.Unlock()
				body.Reset()
				say("250 2.0.0 Ok: queued")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}

		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			if upgradable {
				say("250-fake.example.test")
				say("250-STARTTLS")
				say("250 AUTH PLAIN")
			} else {
				say("250-fake.example.test")
				say("250 AUTH PLAIN")
			}
		case strings.HasPrefix(verb, "STARTTLS"):
			say("220 2.0.0 Ready to start TLS")
			tconn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{f.cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tconn.Handshake(); err != nil {
				return
			}
			// Continue the session on the upgraded connection. The client sends
			// EHLO again after the upgrade, which the loop below answers.
			f.serveUpgraded(tconn)
			return
		case strings.HasPrefix(verb, "AUTH"):
			f.mu.Lock()
			f.authSeen = true
			f.mu.Unlock()
			say("235 2.7.0 Authentication successful")
		case strings.HasPrefix(verb, "MAIL FROM"):
			say("250 2.1.0 Ok")
		case strings.HasPrefix(verb, "RCPT TO"):
			say("250 2.1.5 Ok")
		case strings.HasPrefix(verb, "DATA"):
			inData = true
			say("354 End data with <CR><LF>.<CR><LF>")
		case strings.HasPrefix(verb, "QUIT"):
			say("221 2.0.0 Bye")
			return
		default:
			say("250 2.0.0 Ok")
		}
	}
}

// serveUpgraded continues a session after STARTTLS. Separate from serve because
// the post-upgrade session must not offer STARTTLS again.
func (f *fakeSMTP) serveUpgraded(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	say := func(s string) {
		_, _ = rw.WriteString(s + "\r\n")
		_ = rw.Flush()
	}
	var body strings.Builder
	inData := false
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.received = append(f.received, body.String())
				f.mu.Unlock()
				body.Reset()
				say("250 2.0.0 Ok: queued")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			say("250-fake.example.test")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(verb, "AUTH"):
			f.mu.Lock()
			f.authSeen = true
			f.mu.Unlock()
			say("235 2.7.0 Authentication successful")
		case strings.HasPrefix(verb, "MAIL FROM"):
			say("250 2.1.0 Ok")
		case strings.HasPrefix(verb, "RCPT TO"):
			say("250 2.1.5 Ok")
		case strings.HasPrefix(verb, "DATA"):
			inData = true
			say("354 End data with <CR><LF>.<CR><LF>")
		case strings.HasPrefix(verb, "QUIT"):
			say("221 2.0.0 Bye")
			return
		default:
			say("250 2.0.0 Ok")
		}
	}
}

// pool returns a CertPool trusting this server's certificate, for Config.RootCAs.
func (f *fakeSMTP) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(f.cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	p := x509.NewCertPool()
	p.AddCert(leaf)
	return p
}

// startFakeSMTP listens in the given mode and returns the server plus its port.
func startFakeSMTP(t *testing.T, mode TLSMode) (*fakeSMTP, int) {
	t.Helper()
	f := &fakeSMTP{t: t, cert: selfSignedCert(t)}

	var ln net.Listener
	var err error
	upgradable := mode == TLSModeSTARTTLS
	if upgradable {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{f.cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, upgradable)
		}
	}()
	return f, ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeSMTP) bodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

func (f *fakeSMTP) sawAuth() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authSeen
}

// A welcome email is delivered over STARTTLS, with credentials, and the body
// carries the dashboard link. This is the mode staging runs and nothing covered
// the successful path.
func TestSend_STARTTLS_DeliversTheMessage(t *testing.T) {
	srv, port := startFakeSMTP(t, TLSModeSTARTTLS)
	cfg := testConfig(TLSModeSTARTTLS, "127.0.0.1", port)
	cfg.Username = "apikey"
	cfg.Password = "s3cret"
	cfg.RootCAs = srv.pool(t)
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if err := s.SendWelcome(context.Background(), WelcomeMessage{
		To: "owner@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	bodies := srv.bodies()
	if len(bodies) != 1 {
		t.Fatalf("server accepted %d message(s), want 1", len(bodies))
	}
	for _, want := range []string{"acme", "https://app.example.test", "owner@example.test"} {
		if !strings.Contains(bodies[0], want) {
			t.Errorf("the delivered body does not contain %q:\n%s", want, bodies[0])
		}
	}
	if !srv.sawAuth() {
		t.Error("the sender did not authenticate; net/smtp only sends PlainAuth " +
			"after a successful STARTTLS, so a missing AUTH means the upgrade did not happen")
	}
}

// The same over implicit TLS, so neither mode can lose a step the other keeps.
func TestSend_ImplicitTLS_DeliversTheMessage(t *testing.T) {
	srv, port := startFakeSMTP(t, TLSModeImplicit)
	cfg := testConfig(TLSModeImplicit, "127.0.0.1", port)
	cfg.Username = "apikey"
	cfg.Password = "s3cret"
	cfg.RootCAs = srv.pool(t)
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if err := s.SendInvitation(context.Background(), InvitationMessage{
		To: "invitee@example.test", TenantName: "acme",
		InviterEmail: "owner@example.test",
		AcceptURL:    "https://app.example.test/accept?t=abc",
		ExpiresAt:    time.Now().Add(72 * time.Hour),
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	bodies := srv.bodies()
	if len(bodies) != 1 {
		t.Fatalf("server accepted %d message(s), want 1", len(bodies))
	}
	for _, want := range []string{"acme", "https://app.example.test/accept?t=abc", "owner@example.test"} {
		if !strings.Contains(bodies[0], want) {
			t.Errorf("the delivered body does not contain %q:\n%s", want, bodies[0])
		}
	}
	if !srv.sawAuth() {
		t.Error("the sender did not authenticate over implicit TLS")
	}
}

// With no username, no AUTH is attempted. An unauthenticated relay is a real
// deployment shape and must not be turned into an auth attempt with empty
// credentials.
func TestSend_NoUsernameSkipsAuth(t *testing.T) {
	srv, port := startFakeSMTP(t, TLSModeSTARTTLS)
	cfg := testConfig(TLSModeSTARTTLS, "127.0.0.1", port)
	cfg.RootCAs = srv.pool(t)
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if err := s.SendWelcome(context.Background(), WelcomeMessage{
		To: "owner@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if srv.sawAuth() {
		t.Error("AUTH was attempted with no username configured")
	}
	if len(srv.bodies()) != 1 {
		t.Error("the message was not delivered without auth")
	}
}

// rejectingSMTP fails at one named step with a 5xx, so each step's failure can be
// checked for the mode and the step. Every one of these was an unwrapped
// `fmt.Errorf("smtp mail: %w", err)` before, which told an operator nothing about
// which mode was configured.
type rejectingSMTP struct {
	cert     tls.Certificate
	rejectAt string // "AUTH" | "MAIL FROM" | "RCPT TO" | "DATA"
}

func (r *rejectingSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	say := func(s string) {
		_, _ = rw.WriteString(s + "\r\n")
		_ = rw.Flush()
	}
	say("220 reject.example.test ESMTP")
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		if r.rejectAt != "" && strings.HasPrefix(verb, r.rejectAt) {
			say("550 5.1.1 rejected at " + r.rejectAt)
			continue
		}
		switch {
		case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
			say("250-reject.example.test")
			say("250 AUTH PLAIN")
		case strings.HasPrefix(verb, "AUTH"):
			say("235 2.7.0 Authentication successful")
		case strings.HasPrefix(verb, "MAIL FROM"), strings.HasPrefix(verb, "RCPT TO"):
			say("250 2.1.0 Ok")
		case strings.HasPrefix(verb, "DATA"):
			say("354 End data with <CR><LF>.<CR><LF>")
		case strings.HasPrefix(verb, "QUIT"):
			say("221 2.0.0 Bye")
			return
		case line == ".\r\n":
			say("250 2.0.0 Ok: queued")
		default:
			say("250 2.0.0 Ok")
		}
	}
}

// Each envelope step's rejection reaches the caller naming the step AND the
// configured mode. A bare "smtp rcpt: 550" says neither.
func TestDeliver_EachStepRejectionNamesTheStepAndTheMode(t *testing.T) {
	cases := []struct {
		rejectAt string
		wantStep string
	}{
		{"AUTH", "auth"},
		{"MAIL FROM", "mail from"},
		{"RCPT TO", "rcpt to"},
		{"DATA", "data"},
	}
	for _, tc := range cases {
		t.Run(tc.rejectAt, func(t *testing.T) {
			cert := selfSignedCert(t)
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			srv := &rejectingSMTP{cert: cert, rejectAt: tc.rejectAt}
			go func() {
				for {
					conn, aerr := ln.Accept()
					if aerr != nil {
						return
					}
					go srv.serve(conn)
				}
			}()

			leaf, perr := x509.ParseCertificate(cert.Certificate[0])
			if perr != nil {
				t.Fatalf("parse cert: %v", perr)
			}
			pool := x509.NewCertPool()
			pool.AddCert(leaf)

			cfg := testConfig(TLSModeImplicit, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
			cfg.Username = "apikey"
			cfg.Password = "s3cret"
			cfg.RootCAs = pool
			s, cerr := NewSMTPSender(cfg)
			if cerr != nil {
				t.Fatalf("construct: %v", cerr)
			}

			serr := s.SendWelcome(context.Background(), WelcomeMessage{
				To: "owner@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
			})
			if serr == nil {
				t.Fatalf("want a failure when the server rejects %s", tc.rejectAt)
			}
			msg := serr.Error()
			if !strings.Contains(msg, tc.wantStep) {
				t.Errorf("the failure does not name the step %q: %v", tc.wantStep, serr)
			}
			if !strings.Contains(msg, `"implicit"`) {
				t.Errorf("the failure does not name the configured mode: %v", serr)
			}
		})
	}
}
