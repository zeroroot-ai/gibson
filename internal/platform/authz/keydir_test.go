// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// writeKeyDir writes a key directory (package fgakey) that holds key and no
// previous key, and returns its path.
func writeKeyDir(t *testing.T, key string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key"), []byte(key), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key_previous"), nil, 0o600); err != nil {
		t.Fatalf("write previous key: %v", err)
	}
	return dir
}

// OpenFGA refuses a call with no preshared key, so the client refuses to start
// without one.
func TestNewFgaAuthorizer_RequiresAKey(t *testing.T) {
	cases := map[string]string{
		"no key directory": "",
		"empty directory":  t.TempDir(),
	}
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := NewFgaAuthorizer(context.Background(), FgaConfig{
				Endpoint: "http://fga:8080",
				StoreID:  tlsTestStoreID,
				ModelID:  tlsTestModelID,
				KeyDir:   dir,
			})
			if err == nil {
				t.Fatalf("NewFgaAuthorizer returned %T and no error", a)
			}
			if !IsInvalidArgument(err) {
				t.Errorf("error = %v, want an invalid argument error", err)
			}
		})
	}
}

// Each call to OpenFGA carries the key as a bearer token.
func TestNewFgaAuthorizer_SendsTheKey(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer srv.Close()

	if err := checkOnce(t, FgaConfig{
		Endpoint: srv.URL,
		StoreID:  tlsTestStoreID,
		ModelID:  tlsTestModelID,
		KeyDir:   writeKeyDir(t, "the-key"),
	}); err != nil {
		t.Fatalf("Check: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the server saw no request")
	}
	for _, h := range seen {
		if h != "Bearer the-key" {
			t.Fatalf("Authorization = %q, want the bearer key", h)
		}
	}
}
