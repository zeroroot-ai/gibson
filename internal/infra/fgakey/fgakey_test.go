// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fgakey

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// keyServer is an OpenFGA stand-in: it answers 200 only to a request whose
// bearer key is in accepted, and records each key and body it saw.
type keyServer struct {
	mu       sync.Mutex
	accepted map[string]bool
	seen     []string
	bodies   []string
}

func (s *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	s.seen = append(s.seen, key)
	s.bodies = append(s.bodies, string(body))
	ok := s.accepted[key]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthenticated"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func writeKeys(t *testing.T, dir, current, previous string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, FileKey), []byte(current+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FilePrevious), []byte(previous), 0o600); err != nil {
		t.Fatal(err)
	}
}

func post(t *testing.T, c *http.Client, url, body string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestTransport_SendsTheCurrentKey(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "new-key", "")
	srv := &keyServer{accepted: map[string]bool{"new-key": true}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := HTTPClient(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, c, ts.URL+"/stores", `{"name":"gibson"}`); code != http.StatusOK {
		t.Fatalf("status %d, want 200", code)
	}
	if len(srv.seen) != 1 || srv.seen[0] != "new-key" {
		t.Fatalf("keys sent %v, want [new-key]", srv.seen)
	}
}

// The kubelet wrote the new key to the client, and OpenFGA still runs with
// the old key list: the request goes out again with the previous key, with
// the same body.
func TestTransport_RetriesWithThePreviousKeyOn401(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "new-key", "old-key")
	srv := &keyServer{accepted: map[string]bool{"old-key": true}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := HTTPClient(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, c, ts.URL+"/stores/x/check", `{"tuple_key":{}}`); code != http.StatusOK {
		t.Fatalf("status %d, want 200", code)
	}
	if got := strings.Join(srv.seen, ","); got != "new-key,old-key" {
		t.Fatalf("keys sent %q, want new-key,old-key", got)
	}
	for i, b := range srv.bodies {
		if b != `{"tuple_key":{}}` {
			t.Fatalf("body %d is %q, want the request body", i, b)
		}
	}
}

// A body with no GetBody (a plain io.Reader) is kept for the second send.
func TestTransport_RetryKeepsABodyWithNoGetBody(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "new-key", "old-key")
	srv := &keyServer{accepted: map[string]bool{"old-key": true}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := HTTPClient(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL, io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = nil
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if got := strings.Join(srv.bodies, ","); got != "payload,payload" {
		t.Fatalf("bodies %q, want payload,payload", got)
	}
}

// A key that OpenFGA does not know is refused, and the client gets the 401.
func TestTransport_UnknownKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "stolen", "also-stolen")
	srv := &keyServer{accepted: map[string]bool{"real-key": true}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := HTTPClient(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, c, ts.URL, "{}"); code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", code)
	}
}

// With no previous key, a 401 is the answer: no second request.
func TestTransport_NoPreviousKeyNoRetry(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "new-key", "")
	srv := &keyServer{accepted: map[string]bool{}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	c, err := HTTPClient(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, c, ts.URL, "{}"); code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", code)
	}
	if len(srv.seen) != 1 {
		t.Fatalf("requests %d, want 1", len(srv.seen))
	}
}

// A rotation reaches the client with no restart: after the reload interval
// the transport sends the key that is in the file now.
func TestTransport_FollowsTheKeyFile(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "first", "")
	srv := &keyServer{accepted: map[string]bool{"first": true, "second": true}}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	now := time.Unix(1000, 0)
	rt, err := newTransport(dir, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: rt}
	post(t, c, ts.URL, "{}")
	writeKeys(t, dir, "second", "first")
	post(t, c, ts.URL, "{}")
	now = now.Add(reloadInterval)
	post(t, c, ts.URL, "{}")
	if got := strings.Join(srv.seen, ","); got != "first,first,second" {
		t.Fatalf("keys sent %q, want first,first,second", got)
	}
}

func TestTransport_RefusesToStartWithNoKey(t *testing.T) {
	cases := map[string]func(dir string){
		"no directory": func(string) {},
		"no key file":  func(dir string) { _ = os.Remove(filepath.Join(dir, FileKey)) },
		"empty key":    func(dir string) { writeKeys(t, dir, "  ", "") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if name == "no directory" {
				dir = filepath.Join(dir, "absent")
			} else {
				writeKeys(t, dir, "k", "")
			}
			setup(dir)
			if _, err := Transport(dir, nil); !errors.Is(err, ErrNoKey) {
				t.Fatalf("err %v, want ErrNoKey", err)
			}
		})
	}
	if _, err := Transport("", nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty dir: err %v, want ErrNoKey", err)
	}
}

// A key file that disappears after the start fails the request, so the
// client never sends a call with no key.
func TestTransport_FailsClosedWhenTheKeyGoes(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "k", "")
	now := time.Unix(1000, 0)
	rt, err := newTransport(dir, nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, FileKey)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(reloadInterval)
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	if _, err := rt.RoundTrip(req); !errors.Is(err, ErrNoKey) {
		t.Fatalf("err %v, want ErrNoKey", err)
	}
}

func TestDirFromEnv(t *testing.T) {
	if _, err := DirFromEnv(func(string) string { return "" }); !errors.Is(err, ErrNoKey) {
		t.Fatalf("unset: err %v, want ErrNoKey", err)
	}
	got, err := DirFromEnv(func(k string) string {
		if k == EnvDir {
			return "/etc/gibson/openfga-key"
		}
		return ""
	})
	if err != nil || got != "/etc/gibson/openfga-key" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// HTTPClient keeps the timeout and the transport of the client it copies.
func TestHTTPClient_KeepsTheBaseClient(t *testing.T) {
	dir := t.TempDir()
	writeKeys(t, dir, "k", "")
	base := &http.Client{Timeout: 3 * time.Second, Transport: http.DefaultTransport}
	c, err := HTTPClient(dir, base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout != 3*time.Second {
		t.Fatalf("timeout %s, want 3s", c.Timeout)
	}
	tr, ok := c.Transport.(*transport)
	if !ok || tr.base != http.DefaultTransport {
		t.Fatalf("transport %T does not wrap the base transport", c.Transport)
	}
	if base.Transport != http.DefaultTransport {
		t.Fatal("HTTPClient changed the client it copies")
	}
}
