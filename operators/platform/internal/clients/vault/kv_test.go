// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestKV_WriteThenRead(t *testing.T) {
	stored := map[string]map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		key := r.URL.Path[len("/v1/secret/data/"):]
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Data map[string]string `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			stored[key] = body.Data
			_, _ = w.Write([]byte(`{}`))
		case http.MethodGet:
			d, ok := stored[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d}})
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, func() (string, error) { return "tok", nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.ReadKV(ctx, "gibson-zitadel-iam-admin-pat"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read of a missing entry: %v, want ErrNotFound", err)
	}
	if err := c.WriteKV(ctx, "gibson-zitadel-iam-admin-pat", map[string]string{"pat": "p", "userId": "u"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := c.ReadKV(ctx, "gibson-zitadel-iam-admin-pat")
	if err != nil || got["pat"] != "p" || got["userId"] != "u" {
		t.Fatalf("read = %v, %v", got, err)
	}
}
