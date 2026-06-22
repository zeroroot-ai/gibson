/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

func TestNewTransitClient_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     TransitConfig
		wantErr bool
	}{
		{"missing address", TransitConfig{AuthToken: "tok"}, true},
		{"missing token", TransitConfig{Address: "https://v"}, true},
		{"defaults", TransitConfig{Address: "https://v", AuthToken: "tok"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewTransitClient(c.cfg)
			if c.wantErr && err == nil {
				t.Error("expected error")
			}
			if !c.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestTransit_Derive_HappyPath(t *testing.T) {
	// Mock Vault HMAC endpoint. Deterministic 32-byte hmac for a fixed
	// (key, input) pair — sets up the cache test below.
	const mockHmac = "vault:v1:" + // 32-byte payload base64-encoded:
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/hmac/master-kek/sha2-256" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body hmacRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// We don't actually compute HMAC; just return canned bytes.
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"hmac":%q}}`, mockHmac)
	}))
	defer srv.Close()

	tc, err := NewTransitClient(TransitConfig{
		Address:    srv.URL,
		AuthToken:  "tok",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewTransitClient: %v", err)
	}

	ctx := t.Context()
	out, err := tc.Derive(ctx, "", []byte("zeroroot-ai"), 32)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("got %d bytes, want 32", len(out))
	}
	wantPayload, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(mockHmac, "vault:v1:"))
	for i := range out {
		if out[i] != wantPayload[i] {
			t.Errorf("byte[%d] = %d, want %d", i, out[i], wantPayload[i])
			break
		}
	}
}

func TestTransit_Derive_CacheHit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"hmac":"vault:v1:%s"}}`,
			base64.StdEncoding.EncodeToString(make([]byte, 32)))
	}))
	defer srv.Close()

	tc, _ := NewTransitClient(TransitConfig{Address: srv.URL, AuthToken: "tok", HTTPClient: srv.Client()})

	ctx := t.Context()
	for i := range 5 {
		if _, err := tc.Derive(ctx, "", []byte("acme"), 32); err != nil {
			t.Fatalf("Derive call %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Errorf("Vault was called %d times for 5 same-input Derive calls; want 1 (cache miss + 4 hits)", calls)
	}
}

func TestTransit_Derive_ZeroizeOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Non-zero payload so we can detect zeroing.
		ones := make([]byte, 32)
		for i := range ones {
			ones[i] = 0xAA
		}
		_, _ = fmt.Fprintf(w, `{"data":{"hmac":"vault:v1:%s"}}`, base64.StdEncoding.EncodeToString(ones))
	}))
	defer srv.Close()

	tc, _ := NewTransitClient(TransitConfig{Address: srv.URL, AuthToken: "tok", HTTPClient: srv.Client()})
	tcImpl := tc.(*transitClient)

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := tc.Derive(ctx, "", []byte("acme"), 32); err != nil {
		t.Fatalf("Derive: %v", err)
	}

	// Verify cache populated with non-zero bytes.
	tcImpl.mu.Lock()
	cacheKey := "master-kek:" + "61636d65" // hex("acme")
	v := append([]byte{}, tcImpl.cache[cacheKey]...)
	tcImpl.mu.Unlock()
	if len(v) == 0 {
		t.Fatal("cache empty after Derive")
	}
	allZero := true
	for _, b := range v {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("cache value already zero before cancel")
	}

	// Cancel + give the zeroize goroutine a moment.
	cancel()
	time.Sleep(50 * time.Millisecond)

	tcImpl.mu.Lock()
	_, stillThere := tcImpl.cache[cacheKey]
	tcImpl.mu.Unlock()
	if stillThere {
		t.Error("cache entry not removed after context cancel")
	}
}

func TestTransit_Derive_LengthBounds(t *testing.T) {
	tc, _ := NewTransitClient(TransitConfig{Address: "https://v", AuthToken: "tok"})
	ctx := context.Background()

	if _, err := tc.Derive(ctx, "", []byte("acme"), 0); err == nil {
		t.Error("Derive with length=0 succeeded")
	}
	if _, err := tc.Derive(ctx, "", []byte("acme"), 33); err == nil {
		t.Error("Derive with length=33 succeeded")
	}
	if _, err := tc.Derive(ctx, "", nil, 16); err == nil {
		t.Error("Derive with nil context succeeded")
	}
}

func TestTransit_Derive_TransitNotMounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintln(w, `{"errors":["no handler for route"]}`)
	}))
	defer srv.Close()

	tc, _ := NewTransitClient(TransitConfig{Address: srv.URL, AuthToken: "tok", HTTPClient: srv.Client()})
	_, err := tc.Derive(context.Background(), "", []byte("acme"), 32)
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("error not classified as ErrNotFound: %v", err)
	}
}

func TestTransit_Derive_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintln(w, `{"errors":["permission denied"]}`)
	}))
	defer srv.Close()

	tc, _ := NewTransitClient(TransitConfig{Address: srv.URL, AuthToken: "tok", HTTPClient: srv.Client()})
	_, err := tc.Derive(context.Background(), "", []byte("acme"), 32)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Errorf("error not classified as ErrUnauthorized: %v", err)
	}
}

func TestTransit_Ping(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			hit = true
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintln(w, `{"initialized":true,"sealed":false}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tc, _ := NewTransitClient(TransitConfig{Address: srv.URL, AuthToken: "tok", HTTPClient: srv.Client()})
	if err := tc.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !hit {
		t.Error("Ping did not call /v1/sys/health")
	}
}
