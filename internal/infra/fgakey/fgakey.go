// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fgakey sends the OpenFGA preshared key on each request to OpenFGA.
//
// OpenFGA runs with the preshared key method: its HTTP and gRPC APIs refuse a
// call with no valid key. The chart mounts the key Secret as a directory with
// two files. The file "key" holds the current key. The file "key_previous"
// holds the key before the last rotation, and is empty before the first one
// (ADR-0171).
//
// The transport reads the files again after a short interval, so a rotation
// needs no restart of the client. When OpenFGA refuses the current key with
// 401, the transport sends the request one more time with the previous key.
// This covers the time when the kubelet has written the new key to the client
// and OpenFGA still runs with the old key list.
package fgakey

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// EnvDir names the environment variable that holds the key directory.
	// Each OpenFGA client of the platform reads it.
	EnvDir = "GIBSON_FGA_KEY_DIR"

	// FileKey is the file of the current key in the key directory.
	FileKey = "key"

	// FilePrevious is the file of the previous key in the key directory.
	FilePrevious = "key_previous"

	// reloadInterval is the time after which the transport reads the key
	// files again.
	reloadInterval = 10 * time.Second
)

// ErrNoKey reports that the key directory holds no current key.
var ErrNoKey = errors.New("fgakey: no OpenFGA preshared key")

// DirFromEnv returns the key directory that EnvDir names. An empty value is
// an error: a client of OpenFGA never starts without the key.
func DirFromEnv(getenv func(string) string) (string, error) {
	dir := strings.TrimSpace(getenv(EnvDir))
	if dir == "" {
		return "", fmt.Errorf("%w: %s is not set", ErrNoKey, EnvDir)
	}
	return dir, nil
}

// keys is one read of the key directory.
type keys struct {
	current  string
	previous string
}

// source reads the key directory and keeps the result for reloadInterval.
type source struct {
	dir string
	now func() time.Time

	mu     sync.Mutex
	cached keys
	readAt time.Time
}

func (s *source) load() (keys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.readAt.IsZero() && s.now().Sub(s.readAt) < reloadInterval {
		return s.cached, nil
	}
	k, err := readKeys(s.dir)
	if err != nil {
		return keys{}, err
	}
	s.cached = k
	s.readAt = s.now()
	return k, nil
}

func readKeys(dir string) (keys, error) {
	current, err := readKeyFile(filepath.Join(dir, FileKey))
	if err != nil {
		return keys{}, err
	}
	if current == "" {
		return keys{}, fmt.Errorf("%w: %s is empty", ErrNoKey, filepath.Join(dir, FileKey))
	}
	previous, err := readKeyFile(filepath.Join(dir, FilePrevious))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return keys{}, err
	}
	return keys{current: current, previous: previous}, nil
}

func readKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path is the key directory of the chart, not user input.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: read %s: %w", ErrNoKey, path, err)
		}
		return "", fmt.Errorf("fgakey: read %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// Transport returns a RoundTripper that sends the key of dir on each request
// through base. A nil base means http.DefaultTransport. Transport reads the
// key one time before it returns, so a client with no key fails at start.
func Transport(dir string, base http.RoundTripper) (http.RoundTripper, error) {
	return newTransport(dir, base, time.Now)
}

func newTransport(dir string, base http.RoundTripper, now func() time.Time) (*transport, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("%w: the key directory is empty", ErrNoKey)
	}
	if base == nil {
		base = http.DefaultTransport
	}
	src := &source{dir: dir, now: now}
	if _, err := src.load(); err != nil {
		return nil, err
	}
	return &transport{base: base, src: src}, nil
}

// HTTPClient returns a copy of c whose transport sends the key of dir. A nil
// c means a client with no timeout.
func HTTPClient(dir string, c *http.Client) (*http.Client, error) {
	out := &http.Client{}
	if c != nil {
		*out = *c
	}
	rt, err := Transport(dir, out.Transport)
	if err != nil {
		return nil, err
	}
	out.Transport = rt
	return out, nil
}

type transport struct {
	base http.RoundTripper
	src  *source
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	k, err := t.src.load()
	if err != nil {
		closeBody(req)
		return nil, err
	}
	retry := k.previous != "" && k.previous != k.current
	if retry && req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		// The request must go out two times, so keep its body.
		body, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("fgakey: read the request body: %w", readErr)
		}
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}

	resp, err := t.base.RoundTrip(withKey(req, k.current, req.Body))
	if err != nil || resp.StatusCode != http.StatusUnauthorized || !retry {
		return resp, err //nolint:wrapcheck // a RoundTripper returns the error of its base unchanged.
	}

	var body io.ReadCloser
	if req.GetBody != nil {
		body, err = req.GetBody()
		if err != nil {
			// The first answer stands when the body cannot be sent again.
			return resp, nil //nolint:nilerr // the 401 is the answer.
		}
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return t.base.RoundTrip(withKey(req, k.previous, body)) //nolint:wrapcheck // see above.
}

// withKey returns a copy of req with the key in its Authorization header and
// body as its body. The RoundTripper contract forbids a change of req itself.
func withKey(req *http.Request, key string, body io.ReadCloser) *http.Request {
	out := req.Clone(req.Context())
	out.Body = body
	out.Header.Set("Authorization", "Bearer "+key)
	return out
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
