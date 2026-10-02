// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mail

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func testConfig(mode TLSMode, host string, port int) Config {
	return Config{
		Host:    host,
		Port:    port,
		From:    "noreply@example.test",
		TLSMode: mode,
		// Short on purpose: the point of each mismatch test is that the sender
		// FAILS, and before Config.Timeout was honoured the STARTTLS-against-TLS
		// case blocked forever instead.
		Timeout: 2 * time.Second,
	}
}

// An empty mode is STARTTLS. That is what port 587 and SES want, and it is what
// every deployment that never set the old SMTP_TLS was already getting — so the
// default preserves behaviour across the rename.
func TestNewSMTPSender_EmptyModeDefaultsToSTARTTLS(t *testing.T) {
	s, err := NewSMTPSender(testConfig("", "smtp.example.test", 587))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if s.cfg.TLSMode != TLSModeSTARTTLS {
		t.Errorf("default mode = %q, want %q", s.cfg.TLSMode, TLSModeSTARTTLS)
	}
}

// An unknown mode is refused at construction, naming both modes and the port
// each is normally served on. Accepting it would silently fall through to one of
// the two and the operator would learn which from a handshake error.
func TestNewSMTPSender_RefusesAnUnknownMode(t *testing.T) {
	_, err := NewSMTPSender(testConfig("tls", "smtp.example.test", 587))
	if err == nil {
		t.Fatal("want a refusal for an unknown tls mode")
	}
	for _, want := range []string{`"tls"`, "starttls", "implicit", "587", "465"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// Both named modes construct.
func TestNewSMTPSender_AcceptsBothModes(t *testing.T) {
	for _, mode := range []TLSMode{TLSModeSTARTTLS, TLSModeImplicit} {
		if _, err := NewSMTPSender(testConfig(mode, "smtp.example.test", 587)); err != nil {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
}

// plainListener accepts one connection and says nothing useful. It stands in for
// a STARTTLS port (587): a server that expects EHLO, not a ClientHello.
func plainListener(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			// A plaintext greeting, then nothing. Enough for tls.Dial to fail on
			// a reply that is not a TLS record.
			_, _ = conn.Write([]byte("220 plain.example.test ESMTP\r\n"))
			time.Sleep(50 * time.Millisecond)
			_ = conn.Close()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// selfSignedCert mints a throwaway 127.0.0.1 certificate. Shared with
// sender_delivery_test.go, which needs one to terminate TLS.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsListener accepts TLS connections and nothing else. It stands in for an
// implicit-TLS port (465): a server that expects a ClientHello first.
func tlsListener(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("220 tls.example.test ESMTP\r\n"))
			time.Sleep(50 * time.Millisecond)
			_ = conn.Close()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// Implicit TLS against a STARTTLS port fails with a message that names the
// configured mode, the port, and the mode to try instead. This is the exact
// failure that cost three hours on staging, where the whole error was
// "smtp tls dial: tls: first record does not look like a TLS handshake".
func TestSend_ImplicitAgainstSTARTTLSPort_NamesTheMode(t *testing.T) {
	host, port := plainListener(t)
	s, err := NewSMTPSender(testConfig(TLSModeImplicit, host, port))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	err = s.SendWelcome(context.Background(), WelcomeMessage{
		To: "someone@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
	})
	if err == nil {
		t.Fatal("want a failure: implicit TLS cannot speak to a plaintext port")
	}
	msg := err.Error()
	for _, want := range []string{`"implicit"`, "starttls", host} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}
}

// STARTTLS against an implicit-TLS port fails the same way, naming the mode and
// pointing at the other one. The two failures are symmetric, and before this
// each one read like the other's cause.
func TestSend_STARTTLSAgainstImplicitPort_NamesTheMode(t *testing.T) {
	host, port := tlsListener(t)
	s, err := NewSMTPSender(testConfig(TLSModeSTARTTLS, host, port))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	err = s.SendWelcome(context.Background(), WelcomeMessage{
		To: "someone@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
	})
	if err == nil {
		t.Fatal("want a failure: STARTTLS cannot speak to an implicit-TLS port")
	}
	msg := err.Error()
	for _, want := range []string{`"starttls"`, "implicit", host} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}
}

// The invitation path is wrapped too, not just the welcome path. Both go through
// send(), and a reader checking only one would not notice if they diverged.
func TestSendInvitation_AlsoNamesTheMode(t *testing.T) {
	host, port := plainListener(t)
	s, err := NewSMTPSender(testConfig(TLSModeImplicit, host, port))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	err = s.SendInvitation(context.Background(), InvitationMessage{
		To: "someone@example.test", TenantName: "acme",
		InviterEmail: "owner@example.test", AcceptURL: "https://app.example.test/accept",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("want a failure")
	}
	if !strings.Contains(err.Error(), `"implicit"`) {
		t.Errorf("the invitation failure does not name the mode: %v", err)
	}
}

// Required fields are refused by name. A sender constructed without a From would
// fail at the first MAIL FROM, from inside a reconcile, instead of at startup.
func TestNewSMTPSender_RefusesMissingRequiredFields(t *testing.T) {
	cases := map[string]Config{
		"no host": {Port: 587, From: "a@b.test"},
		"no port": {Host: "smtp.example.test", From: "a@b.test"},
		"no from": {Host: "smtp.example.test", Port: 587},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSMTPSender(cfg); err == nil {
				t.Fatal("want a refusal")
			} else if !strings.Contains(err.Error(), "required") {
				t.Errorf("the refusal does not say what is required: %v", err)
			}
		})
	}
}

// A zero Timeout becomes 30s rather than staying zero. Zero would mean "no
// timeout" to net.DialTimeout, which is the unbounded reconcile this change
// exists to remove.
func TestNewSMTPSender_ZeroTimeoutBecomesABound(t *testing.T) {
	s, err := NewSMTPSender(Config{Host: "smtp.example.test", Port: 587, From: "a@b.test"})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if s.cfg.Timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s — zero means no timeout to net.DialTimeout",
			s.cfg.Timeout)
	}
}

// A refused connection fails in both modes with the mode named, rather than
// surfacing a bare "connection refused" that says nothing about configuration.
func TestSend_DialFailureNamesTheMode(t *testing.T) {
	// Bind and close, so the port is almost certainly free and refusing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	for _, mode := range []TLSMode{TLSModeSTARTTLS, TLSModeImplicit} {
		t.Run(string(mode), func(t *testing.T) {
			s, cerr := NewSMTPSender(testConfig(mode, "127.0.0.1", port))
			if cerr != nil {
				t.Fatalf("construct: %v", cerr)
			}
			serr := s.SendWelcome(context.Background(), WelcomeMessage{
				To: "owner@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
			})
			if serr == nil {
				t.Fatal("want a failure dialling a closed port")
			}
			if !strings.Contains(serr.Error(), string(mode)) {
				t.Errorf("the failure does not name the mode %q: %v", mode, serr)
			}
			if !strings.Contains(serr.Error(), "dial") {
				t.Errorf("the failure does not say it was the dial: %v", serr)
			}
		})
	}
}

// A server that greets but does not offer STARTTLS fails with "starttls" named.
// net/smtp will not send PlainAuth over the un-upgraded link, so this is the
// failure that protects the credentials — it should say so.
func TestSend_ServerWithoutSTARTTLS_NamesTheUpgrade(t *testing.T) {
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
				_, _ = c.Write([]byte("220 nostarttls.example.test ESMTP\r\n"))
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					up := strings.ToUpper(strings.TrimRight(line, "\r\n"))
					switch {
					case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
						// No STARTTLS in the capability list.
						_, _ = c.Write([]byte("250-nostarttls.example.test\r\n250 AUTH PLAIN\r\n"))
					case strings.HasPrefix(up, "QUIT"):
						_, _ = c.Write([]byte("221 2.0.0 Bye\r\n"))
						return
					default:
						_, _ = c.Write([]byte("502 5.5.1 Not implemented\r\n"))
					}
				}
			}(conn)
		}
	}()

	s, err := NewSMTPSender(testConfig(TLSModeSTARTTLS, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	serr := s.SendWelcome(context.Background(), WelcomeMessage{
		To: "owner@example.test", TenantName: "acme", DashboardURL: "https://app.example.test",
	})
	if serr == nil {
		t.Fatal("want a failure against a server that does not offer STARTTLS")
	}
	if !strings.Contains(serr.Error(), "starttls") {
		t.Errorf("the failure does not name the upgrade: %v", serr)
	}
}
