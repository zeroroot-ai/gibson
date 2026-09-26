// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fga is platform-operator's internal OpenFGA HTTP client.
// Owns the minimum API surface needed by PlatformBootstrap's FGA model
// load step (ensure a named store, write an authorization model from
// DSL/JSON, return the resulting model ID) and by the Platform owner
// reconcile step (ADR-0093 decision 6, hosted#201): check and write the
// single `platform_owner` tuple on `system_tenant:_system`.
package fga

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrNotFound    = errors.New("fga: not found")
	ErrUnreachable = errors.New("fga: unreachable")
	ErrInvalid     = errors.New("fga: invalid input")
)

// Client is the OpenFGA HTTP client surface.
type Client interface {
	// EnsureStore creates a store with the given name and returns its
	// ID. Idempotent: existing store by name returns the existing ID.
	EnsureStore(ctx context.Context, name string) (storeID string, err error)

	// WriteAuthorizationModel uploads a model and returns the resulting
	// model ID.
	WriteAuthorizationModel(ctx context.Context, storeID string, model []byte) (modelID string, err error)

	// Check returns whether (user, relation, object) currently holds under
	// modelID — a direct grant or a computed-union path. Used by WriteTuple's
	// idempotency check and by callers that only need a read.
	Check(ctx context.Context, storeID, modelID, user, relation, object string) (bool, error)

	// WriteTuple writes the direct tuple (user, relation, object). Idempotent
	// for a relation with no computed-union path to true other than this
	// exact direct grant (true of platform_owner: [user], the only relation
	// this method is used for): it Checks first and no-ops when the tuple
	// already holds, because OpenFGA's own Write errors on a duplicate write
	// rather than treating it as a no-op.
	WriteTuple(ctx context.Context, storeID, modelID, user, relation, object string) error
}

// New returns an HTTP client at the given base URL.
func New(apiURL string) (Client, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("fga: invalid apiURL %q: %w", apiURL, ErrInvalid)
	}
	return &httpClient{
		baseURL: u,
		http:    &http.Client{Timeout: 30 * time.Second},
	}, nil
}

type httpClient struct {
	baseURL *url.URL
	http    *http.Client
}

func (c *httpClient) EnsureStore(ctx context.Context, name string) (string, error) {
	// Search for existing store first.
	var list struct {
		Stores []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"stores"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/stores", nil, &list); err != nil {
		return "", err
	}
	for _, s := range list.Stores {
		if s.Name == name {
			return s.ID, nil
		}
	}
	// Create.
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/stores", map[string]any{"name": name}, &resp); err != nil {
		return "", fmt.Errorf("EnsureStore %q: %w", name, err)
	}
	return resp.ID, nil
}

func (c *httpClient) WriteAuthorizationModel(ctx context.Context, storeID string, model []byte) (string, error) {
	// Accept either parsed JSON or raw DSL (caller decides). We pass
	// through as JSON body — FGA expects {"type_definitions":[...]}.
	// For DSL input the caller should run the OpenFGA SDK's translator
	// before submission. Here we trust the input is already JSON.
	var body any
	if err := json.Unmarshal(model, &body); err != nil {
		return "", fmt.Errorf("WriteAuthorizationModel: parse model JSON: %w: %w", err, ErrInvalid)
	}
	path := fmt.Sprintf("/stores/%s/authorization-models", url.PathEscape(storeID))
	var resp struct {
		AuthorizationModelID string `json:"authorization_model_id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return "", fmt.Errorf("WriteAuthorizationModel store=%s: %w", storeID, err)
	}
	return resp.AuthorizationModelID, nil
}

// Check implements Client.
//
// OpenFGA: POST /stores/{store_id}/check with
// {"tuple_key":{"user":..,"relation":..,"object":..},"authorization_model_id":..}
// returns {"allowed": bool}.
func (c *httpClient) Check(ctx context.Context, storeID, modelID, user, relation, object string) (bool, error) {
	path := fmt.Sprintf("/stores/%s/check", url.PathEscape(storeID))
	body := map[string]any{
		"tuple_key": map[string]any{
			"user":     user,
			"relation": relation,
			"object":   object,
		},
		"authorization_model_id": modelID,
	}
	var resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return false, fmt.Errorf("Check store=%s %s %s %s: %w", storeID, user, relation, object, err)
	}
	return resp.Allowed, nil
}

// WriteTuple implements Client.
//
// OpenFGA: POST /stores/{store_id}/write with
// {"writes":{"tuple_keys":[{"user":..,"relation":..,"object":..}]},"authorization_model_id":..}.
func (c *httpClient) WriteTuple(ctx context.Context, storeID, modelID, user, relation, object string) error {
	allowed, err := c.Check(ctx, storeID, modelID, user, relation, object)
	if err != nil {
		return fmt.Errorf("WriteTuple: precheck: %w", err)
	}
	if allowed {
		return nil
	}
	path := fmt.Sprintf("/stores/%s/write", url.PathEscape(storeID))
	body := map[string]any{
		"writes": map[string]any{
			"tuple_keys": []map[string]any{
				{"user": user, "relation": relation, "object": object},
			},
		},
		"authorization_model_id": modelID,
	}
	if err := c.doJSON(ctx, http.MethodPost, path, body, nil); err != nil {
		return fmt.Errorf("WriteTuple store=%s %s %s %s: %w", storeID, user, relation, object, err)
	}
	return nil
}

func (c *httpClient) doJSON(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fga: marshal: %w", err)
		}
		rdr = bytes.NewReader(buf)
	}
	full, err := c.baseURL.Parse(path)
	if err != nil {
		return fmt.Errorf("fga: path %q: %w", path, ErrInvalid)
	}
	req, err := http.NewRequestWithContext(ctx, method, full.String(), rdr)
	if err != nil {
		return fmt.Errorf("fga: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fga: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		return json.Unmarshal(raw, out)
	}
	if resp.StatusCode == 404 {
		return fmt.Errorf("fga %s %s 404: %w", method, path, ErrNotFound)
	}
	return fmt.Errorf("fga %s %s %d: %s", method, path, resp.StatusCode, string(raw))
}
