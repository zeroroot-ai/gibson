// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// HTTPClient implements Client against the OpenFGA HTTP API.
type HTTPClient struct {
	baseURL *url.URL
	storeID string
	modelID string
	token   string
	http    *http.Client
}

// NewHTTPClient constructs an OpenFGA HTTP client.
func NewHTTPClient(cfg Config) (*HTTPClient, error) {
	if cfg.BaseURL == "" || cfg.StoreID == "" {
		return nil, fmt.Errorf("fga: BaseURL and StoreID required: %w", clients.ErrInvalidInput)
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("fga: parse BaseURL: %w", clients.ErrInvalidInput)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &HTTPClient{
		baseURL: u,
		storeID: cfg.StoreID,
		modelID: cfg.ModelID,
		token:   cfg.APIToken,
		http:    &http.Client{Timeout: timeout},
	}, nil
}

// Write implements Client.
func (c *HTTPClient) Write(ctx context.Context, tuples []Tuple) error {
	if len(tuples) == 0 {
		return nil
	}
	start := time.Now()
	body := map[string]any{
		"authorization_model_id": c.modelID,
		"writes": map[string]any{
			"tuple_keys": toTupleKeys(tuples),
		},
	}
	err := c.doJSON(ctx, fmt.Sprintf("/stores/%s/write", c.storeID), body, nil)
	metrics.ObserveSubsystemCall("fga", "Write", start, err)
	return err
}

// Delete implements Client.
func (c *HTTPClient) Delete(ctx context.Context, tuples []Tuple) error {
	if len(tuples) == 0 {
		return nil
	}
	start := time.Now()
	body := map[string]any{
		"authorization_model_id": c.modelID,
		"deletes": map[string]any{
			"tuple_keys": toTupleKeys(tuples),
		},
	}
	err := c.doJSON(ctx, fmt.Sprintf("/stores/%s/write", c.storeID), body, nil)
	// Delete of non-existent tuple is idempotent.
	if err != nil && errors.Is(err, clients.ErrNotFound) {
		metrics.ObserveSubsystemCall("fga", "Delete", start, nil)
		return nil
	}
	metrics.ObserveSubsystemCall("fga", "Delete", start, err)
	return err
}

// Read implements Client.
func (c *HTTPClient) Read(ctx context.Context, filter Tuple) ([]Tuple, error) {
	start := time.Now()
	body := map[string]any{
		"tuple_key": tupleKey(filter),
	}
	var resp struct {
		Tuples []struct {
			Key struct {
				User     string `json:"user"`
				Relation string `json:"relation"`
				Object   string `json:"object"`
			} `json:"key"`
		} `json:"tuples"`
	}
	err := c.doJSON(ctx, fmt.Sprintf("/stores/%s/read", c.storeID), body, &resp)
	metrics.ObserveSubsystemCall("fga", "Read", start, err)
	if err != nil {
		return nil, err
	}
	out := make([]Tuple, 0, len(resp.Tuples))
	for _, t := range resp.Tuples {
		out = append(out, Tuple{User: t.Key.User, Relation: t.Key.Relation, Object: t.Key.Object})
	}
	return out, nil
}

// Check implements Client.
func (c *HTTPClient) Check(ctx context.Context, user, relation, object string) (bool, error) {
	start := time.Now()
	body := map[string]any{
		"authorization_model_id": c.modelID,
		"tuple_key": map[string]string{
			"user":     user,
			"relation": relation,
			"object":   object,
		},
	}
	var resp struct {
		Allowed bool `json:"allowed"`
	}
	err := c.doJSON(ctx, fmt.Sprintf("/stores/%s/check", c.storeID), body, &resp)
	metrics.ObserveSubsystemCall("fga", "Check", start, err)
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

// Ping implements Client. Calls the OpenFGA `/healthz` endpoint which returns
// {"status":"SERVING"} on a healthy store. Using the top-level health endpoint
// avoids sending a malformed Read (which fails with 400 validation_error)
// and also works before any store exists.
func (c *HTTPClient) Ping(ctx context.Context) error {
	ref, err := url.Parse("/healthz")
	if err != nil {
		return err
	}
	u := c.baseURL.ResolveReference(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fga /healthz: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return clients.WrapPermanent(fmt.Errorf("fga /healthz %d", resp.StatusCode))
	}
	return fmt.Errorf("fga /healthz %d", resp.StatusCode)
}

func toTupleKeys(tuples []Tuple) []map[string]string {
	out := make([]map[string]string, len(tuples))
	for i, t := range tuples {
		out[i] = tupleKey(t)
	}
	return out
}

func tupleKey(t Tuple) map[string]string {
	m := map[string]string{}
	if t.User != "" {
		m["user"] = t.User
	}
	if t.Relation != "" {
		m["relation"] = t.Relation
	}
	if t.Object != "" {
		m["object"] = t.Object
	}
	return m
}

func (c *HTTPClient) doJSON(ctx context.Context, path string, body any, out any) error {
	ref, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("fga: path %q: %w", path, clients.ErrInvalidInput)
	}
	u := c.baseURL.ResolveReference(ref)

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("fga: marshal: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	// All FGA calls today are POST; hardcoded since unparam flagged
	// the only caller passes http.MethodPost. If a GET/PUT shape ever
	// returns, restore the method param.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("fga: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fga: %v: %w", err, clients.ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("fga: decode: %w", err)
		}
		return nil
	}
	// OpenFGA returns 400 with code "write_failed_due_to_invalid_input" and a
	// body mentioning "tuple to be written already existed" when a write would
	// duplicate an existing tuple. That's a conflict, not a true validation
	// error — surface it as ErrAlreadyExists so idempotent steps treat it as
	// success.
	bodyStr := string(raw)
	if resp.StatusCode == http.StatusBadRequest &&
		strings.Contains(bodyStr, "tuple to be written already existed") {
		return fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrAlreadyExists)
	}
	if resp.StatusCode == http.StatusBadRequest &&
		strings.Contains(bodyStr, "tuple to be deleted did not exist") {
		return fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrNotFound)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrNotFound)
	case resp.StatusCode == http.StatusConflict:
		return fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrAlreadyExists)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Auth failures require credential rotation — permanent.
		return clients.WrapPermanent(fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrUnauthorized))
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("fga %d: %w", resp.StatusCode, clients.ErrRateLimited)
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Distinguish permanent config errors (bad store/model ID) from transient 4xx.
		// OpenFGA uses "invalid_store_id" and "invalid_model" error codes.
		if strings.Contains(bodyStr, "invalid_store_id") || strings.Contains(bodyStr, "invalid_model") {
			return clients.WrapPermanent(fmt.Errorf("fga %d: %w: %s", resp.StatusCode, clients.ErrInvalidInput, bodyStr))
		}
		return fmt.Errorf("fga %d: %w: %s", resp.StatusCode, clients.ErrInvalidInput, bodyStr)
	default:
		return fmt.Errorf("fga %d: %w: %s", resp.StatusCode, clients.ErrUnreachable, bodyStr)
	}
}
