// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

// HeaderCapabilityGrant carries the Capability Grant of a call.
const HeaderCapabilityGrant = "x-capability-grant"

// maxResponseBytes caps the body of a reply that the client reads in full. It
// matches the gateway buffer.
const maxResponseBytes = 16 << 20

// maxErrorBytes caps the part of an error body that the client keeps.
const maxErrorBytes = 2048

// Target names where a call goes: one provider of one tenant, and one exact
// model name. The caller resolves a slot to a Target before the call.
type Target struct {
	// Tenant is the tenant of the route.
	Tenant string
	// Provider is the name of the ModelProvider of the tenant.
	Provider string
	// Model is the exact model name. The gateway sends it to ext-authz.
	Model string
}

func (t Target) validate(needModel bool) error {
	switch {
	case t.Tenant == "":
		return errors.New("modelclient: the target has no tenant")
	case t.Provider == "":
		return errors.New("modelclient: the target has no provider")
	case needModel && t.Model == "":
		return errors.New("modelclient: the target has no exact model name")
	}
	return nil
}

// Caller says who makes the call, and for which work. The GrantSource signs a
// Capability Grant from it.
type Caller struct {
	// Tenant is the tenant of the work. It must equal the tenant of the Target.
	Tenant string
	// Mission and Task scope the grant. ext-authz refuses a call of a mission
	// that is not running.
	Mission string
	Task    string
	// Initiator is the person who created the mission, as an FGA user
	// ("user:<id>"). It is the subject of the model access check. It may be empty.
	Initiator string
	// Purpose names the part of the daemon that makes the call, for the grant
	// subject and for audit. For example "brain-decider".
	Purpose string
}

// GrantSource returns the Capability Grant for one call. The daemon implements
// it with its own signing key. It never returns a grant for another tenant.
type GrantSource interface {
	Grant(ctx context.Context, caller Caller) (string, error)
}

// Config configures a Client.
type Config struct {
	// BaseURL is the URL of the model gateway, for example
	// "http://model-gateway.gibson-gateway.svc:8080". Required.
	BaseURL string
	// Grants signs the identity of each call. Required.
	Grants GrantSource
	// HTTPClient sends the calls. It has no overall timeout of its own, so a
	// stream can run. The caller sets a deadline on the context.
	HTTPClient *http.Client
}

// Client sends model calls to the model gateway.
type Client struct {
	base   string
	grants GrantSource
	http   *http.Client
}

// New returns a Client.
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("modelclient: the gateway URL is required")
	}
	if cfg.Grants == nil {
		return nil, errors.New("modelclient: the grant source is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	return &Client{base: base, grants: cfg.Grants, http: hc}, nil
}

// APIError is a refusal or a failure that the gateway returned.
type APIError struct {
	// Status is the HTTP status.
	Status int
	// Body is the start of the reply body.
	Body string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("model gateway answered %d: %s", e.Status, e.Body)
}

// Refused reports whether the gateway refused the call by policy (401 or 403).
// A retry does not help.
func (e *APIError) Refused() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// NoRoute reports whether no route matched (404). A provider that was saved a
// moment ago has no route until the operator has rendered it.
func (e *APIError) NoRoute() bool { return e.Status == http.StatusNotFound }

// Retryable reports whether a later call can succeed.
func (e *APIError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500 || e.NoRoute()
}

// send builds and sends one request to a route of the target. The caller closes
// the body of a response with status 2xx. On any other status, send reads the
// start of the body, closes it, and returns an APIError.
func (c *Client) send(
	ctx context.Context, caller Caller, target Target, method, path string, body []byte, accept string,
) (*http.Response, error) {
	if caller.Tenant != target.Tenant {
		return nil, fmt.Errorf("modelclient: the caller tenant %q is not the target tenant %q",
			caller.Tenant, target.Tenant)
	}
	grant, err := c.grants.Grant(ctx, caller)
	if err != nil {
		return nil, fmt.Errorf("modelclient: sign the grant: %w", err)
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("modelclient: build the request: %w", err)
	}
	for _, h := range modelcall.RouteHeaders(target.Tenant, target.Provider) {
		req.Header.Set(h.Name, h.Value)
	}
	req.Header.Set(HeaderCapabilityGrant, grant)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", accept)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("modelclient: send to the gateway: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return nil, &APIError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	return resp, nil
}

// Respond sends one Open Responses call and returns the whole reply. The model
// of the request is the model of the target.
func (c *Client) Respond(ctx context.Context, caller Caller, target Target, req Request) (*Response, error) {
	if err := target.validate(true); err != nil {
		return nil, err
	}
	req.Model = target.Model
	req.Stream = false
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("modelclient: encode the request: %w", err)
	}
	resp, err := c.send(ctx, caller, target, http.MethodPost, modelcall.RouteResponses, body, "application/json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("modelclient: read the reply: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, errors.New("modelclient: the reply is larger than the gateway buffer")
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("modelclient: decode the reply: %w", err)
	}
	if out.Error != nil {
		return nil, &ResponseFailure{Code: out.Error.Code, Message: out.Error.Message}
	}
	return &out, nil
}

// ResponseFailure is a reply with status 2xx that holds an error object.
type ResponseFailure struct {
	Code    string
	Message string
}

func (e *ResponseFailure) Error() string {
	return fmt.Sprintf("the model reported a failure (%s): %s", e.Code, e.Message)
}
