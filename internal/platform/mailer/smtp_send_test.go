// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// failAt is a writer that accepts n bytes and then fails every write.
type failAt struct {
	n       int
	written int
}

func (f *failAt) Write(p []byte) (int, error) {
	if f.written+len(p) > f.n {
		accepted := f.n - f.written
		f.written = f.n
		return accepted, errors.New("the writer failed")
	}
	f.written += len(p)
	return len(p), nil
}

// TestWriteRFC822_ReportsAWriteFailureAtAnyOffset fails the writer at every
// byte offset of the message and expects an error each time. A write that
// fails in the middle of a part and goes unreported would send a cut message.
func TestWriteRFC822_ReportsAWriteFailureAtAnyOffset(t *testing.T) {
	m := &SMTPMailer{from: "no-reply@example.com", configurationSet: "gibson-transactional"}
	for name, msg := range map[string]Message{
		"text only": {To: "a@example.com", Subject: "Hi", Text: strings.Repeat("plain text ", 20) + "\nend"},
		"multipart": {To: "a@example.com", Subject: "Hi", Text: "plain\nend", HTML: strings.Repeat("<p>rich</p>\n", 10)},
	} {
		full, err := m.buildRFC822(msg)
		if err != nil {
			t.Fatalf("%s: buildRFC822: %v", name, err)
		}
		for n := range full {
			if err := m.writeRFC822(&failAt{n: n}, msg); err == nil {
				t.Fatalf("%s: a write failure after %d of %d bytes went unreported", name, n, len(full))
			}
		}
	}
}

// TestSMTPMailer_SendReportsARelayThatIsDown sends to a port that nothing
// listens on. The error names the recipient and wraps the dial error.
func TestSMTPMailer_SendReportsARelayThatIsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	_ = ln.Close() // The port is free again, and nothing listens on it.

	m := &SMTPMailer{from: "no-reply@example.com", host: host, port: port}
	err = m.Send(context.Background(), Message{To: "a@example.com", Subject: "Hi", Text: "plain"})
	if err == nil {
		t.Fatal("Send returned nil with no relay")
	}
	if !strings.Contains(err.Error(), "send to a@example.com") {
		t.Errorf("error = %q, want the recipient in it", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Errorf("error = %q, want the wrapped dial error", err)
	}
}

// serveOneSMTPMessage answers one SMTP session with no extensions and sends
// the bytes of the DATA command, with the dot stuffing removed and the line
// ends kept, on got.
func serveOneSMTPMessage(ln net.Listener, got chan<- []byte) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	reply := func(line string) { _, _ = fmt.Fprintf(conn, "%s\r\n", line) }
	r := bufio.NewReader(conn)
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		verb, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch strings.ToUpper(verb) {
		case "DATA":
			reply("354 send the message")
			var data strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(strings.TrimPrefix(l, "."))
			}
			reply("250 queued")
			got <- []byte(data.String())
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 OK")
		}
	}
}

// TestSMTPMailer_SendDeliversAValidMultipartAlternative runs Send against a
// local SMTP server and parses the bytes that the server receives. This is
// the message as a relay sees it, after net/smtp wrote it.
func TestSMTPMailer_SendDeliversAValidMultipartAlternative(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan []byte, 1)
	go serveOneSMTPMessage(ln, got)

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	m := &SMTPMailer{from: "no-reply@example.com", host: host, port: port}
	if err := m.Send(context.Background(), onboardingMessage(t)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case raw := <-got:
		assertMultipartAlternative(t, raw, onboardingMessage(t))
	case <-time.After(10 * time.Second):
		t.Fatal("the server received no message")
	}
}
