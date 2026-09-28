// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// SMTPProviderConfig is the SMTP email provider settings the reconciler
// wants applied. It maps 1:1 onto Zitadel v4.18.0's AddEmailProviderSMTP /
// UpdateEmailProviderSMTP request fields (proto
// zitadel/admin.proto:AddEmailProviderSMTPRequest /
// UpdateEmailProviderSMTPRequest) — see toSMTPProviderBody for the exact
// field-by-field mapping.
type SMTPProviderConfig struct {
	// SenderAddress is the envelope/header From address (proto
	// sender_address, REQUIRED, 1-200 chars).
	SenderAddress string
	// SenderName is the display name attached to SenderAddress (proto
	// sender_name, REQUIRED, 1-200 chars).
	SenderName string
	// TLS enables STARTTLS (proto tls).
	TLS bool
	// Host is "host:port" — Zitadel expects the port folded into this one
	// field (proto host, REQUIRED, 1-500 chars; the field's own description
	// literally says "Make sure to include the port.").
	Host string
	// User is the SMTP username (proto user). Empty means no
	// authentication: the request sets the "none" arm of the Auth oneof
	// (SMTPNoAuth) instead of "plain".
	User string
	// Password is the SMTP password, sent via the Auth oneof's "plain" arm
	// (SMTPPlainAuth.password) rather than the request's own deprecated
	// top-level password field. Ignored when User is empty.
	Password string
	// ReplyToAddress is optional (proto reply_to_address, 0-200 chars).
	ReplyToAddress string
	// Description tags the provider so FindSMTPEmailProviderByDescription
	// can recover its id later (proto description, 0-200 chars).
	Description string
}

// SMTPProviderState is the live settings + activation state Zitadel reports
// back for one email provider (proto zitadel/settings.proto:EmailProvider /
// EmailProviderSMTP). Zitadel never echoes back the password.
type SMTPProviderState struct {
	// ID is the provider's management-API id.
	ID string
	// Active reports whether this is the instance's one ACTIVE email
	// provider (proto EmailProviderState — EMAIL_PROVIDER_ACTIVE).
	Active bool
	// IsSMTP reports whether the provider's config is the smtp arm of the
	// EmailProvider oneof, as opposed to the http arm (EmailProviderHTTP). A
	// provider this reconciler ever created is always SMTP; false here means
	// something else (out of this reconciler's scope) is occupying the
	// provider id, and every field below is zero.
	IsSMTP bool
	// SenderAddress, SenderName, TLS, Host, User, ReplyToAddress mirror
	// SMTPProviderConfig's fields as Zitadel currently has them stored.
	SenderAddress  string
	SenderName     string
	TLS            bool
	Host           string
	User           string
	ReplyToAddress string
}

// Matches reports whether live state's comparable fields (every field
// Zitadel actually echoes back — everything except the password, which
// Zitadel never returns) equal cfg. The caller tracks the password
// separately via a settings hash (PlatformBootstrapStatus.smtpSettingsHash).
func (s SMTPProviderState) Matches(cfg SMTPProviderConfig) bool {
	return s.IsSMTP &&
		s.SenderAddress == cfg.SenderAddress &&
		s.SenderName == cfg.SenderName &&
		s.TLS == cfg.TLS &&
		s.Host == cfg.Host &&
		s.User == cfg.User &&
		s.ReplyToAddress == cfg.ReplyToAddress
}

// EmailProviderClient is the Zitadel instance SMTP email provider surface
// (hosted#189: Zitadel has no mail server configured out of the box, so
// every Zitadel-sent email — Platform owner setup link, tenant Owner setup
// link, invitations, an MFA reset routed through Zitadel — is silently
// undeliverable until something calls these).
//
// Zitadel v4.18.0 deprecated the older /admin/v1/smtp/* surface
// (AddSMTPConfig, ListSMTPConfigs, ...) in favor of the /admin/v1/email/*
// surface below (AddEmailProviderSMTP, ...), which additionally supports
// non-SMTP (HTTP) providers via the same "one active provider" model. Every
// method here uses the non-deprecated surface.
type EmailProviderClient interface {
	// AddSMTPEmailProvider creates a new SMTP email provider and returns its
	// id. It does NOT activate it — call ActivateEmailProvider afterward.
	//
	// Zitadel v4.18.0: POST /admin/v1/email/smtp (AddEmailProviderSMTP).
	AddSMTPEmailProvider(ctx context.Context, cfg SMTPProviderConfig) (id string, err error)

	// UpdateSMTPEmailProvider replaces every field of the SMTP provider id
	// with cfg, INCLUDING the password (sent every call via the Auth
	// oneof's "plain" arm — Zitadel has no partial-update path for a single
	// field here, mirroring EnsureJWTAccessToken's full-replace GET+PUT
	// pattern elsewhere in this client). Does not change activation state.
	//
	// Zitadel v4.18.0: PUT /admin/v1/email/smtp/{id} (UpdateEmailProviderSMTP).
	UpdateSMTPEmailProvider(ctx context.Context, id string, cfg SMTPProviderConfig) error

	// ActivateEmailProvider makes the email provider id the instance's one
	// active provider. Idempotent: Zitadel does not error on an
	// already-active provider.
	//
	// Zitadel v4.18.0: POST /admin/v1/email/{id}/_activate (ActivateEmailProvider).
	ActivateEmailProvider(ctx context.Context, id string) error

	// FindSMTPEmailProviderByDescription searches every configured email
	// provider (active or not) for one whose description matches exactly,
	// returning its id. Returns ErrNotFound when no match. Used to recover
	// the provider id when PlatformBootstrapStatus.smtpProviderID is empty
	// (a fresh install, or a status wiped by CR recreation) without ever
	// creating a second provider for the same description.
	//
	// Zitadel v4.18.0: POST /admin/v1/email/_search (ListEmailProviders).
	FindSMTPEmailProviderByDescription(ctx context.Context, description string) (id string, err error)

	// GetSMTPEmailProviderState looks up the email provider id and reports
	// its live settings + activation state. Returns ErrNotFound when the id
	// no longer exists (removed out from under the operator).
	//
	// Zitadel v4.18.0: GET /admin/v1/email/{id} (GetEmailProviderById).
	GetSMTPEmailProviderState(ctx context.Context, id string) (SMTPProviderState, error)

	// IsSMTPProviderActive reports whether the instance's currently active
	// email provider (there is at most one) is an SMTP provider. Returns
	// (false, nil) when no provider is active at all — this is the normal
	// "brand-new instance" state, not an error.
	//
	// Used to gate the Platform owner's mailed setup link (hosted#189):
	// Zitadel's CreateInviteCode "succeeds" and queues a notification even
	// with no mail transport configured at all, so the caller must check
	// this directly rather than trust CreateInviteCode's own (lack of an)
	// error.
	//
	// Zitadel v4.18.0: GET /admin/v1/email (GetEmailProvider).
	IsSMTPProviderActive(ctx context.Context) (bool, error)
}

// toSMTPProviderBody renders cfg as the protojson body AddEmailProviderSMTP
// / UpdateEmailProviderSMTP expect (proto zitadel/admin.proto). Every key is
// the field's protojson (lowerCamelCase) name; the Auth oneof is rendered as
// a top-level key named after whichever arm is chosen — "none": {} or
// "plain": {"password": ...} — which is how protojson serializes a oneof,
// never a wrapper field named "auth".
func toSMTPProviderBody(cfg SMTPProviderConfig) map[string]any {
	body := map[string]any{
		"senderAddress": cfg.SenderAddress,
		"senderName":    cfg.SenderName,
		"tls":           cfg.TLS,
		"host":          cfg.Host,
	}
	if cfg.ReplyToAddress != "" {
		body["replyToAddress"] = cfg.ReplyToAddress
	}
	if cfg.Description != "" {
		body["description"] = cfg.Description
	}
	if cfg.User == "" {
		body["none"] = map[string]any{}
		return body
	}
	body["user"] = cfg.User
	body["plain"] = map[string]any{"password": cfg.Password}
	return body
}

// errClient stubs — every EmailProviderClient method returns the
// construction error errClient was built to report, matching every other
// interface's errClient stub in this package.
func (e *errClient) AddSMTPEmailProvider(context.Context, SMTPProviderConfig) (string, error) {
	return "", e.err
}
func (e *errClient) UpdateSMTPEmailProvider(context.Context, string, SMTPProviderConfig) error {
	return e.err
}
func (e *errClient) ActivateEmailProvider(context.Context, string) error { return e.err }
func (e *errClient) FindSMTPEmailProviderByDescription(context.Context, string) (string, error) {
	return "", e.err
}
func (e *errClient) GetSMTPEmailProviderState(context.Context, string) (SMTPProviderState, error) {
	return SMTPProviderState{}, e.err
}
func (e *errClient) IsSMTPProviderActive(context.Context) (bool, error) { return false, e.err }

// AddSMTPEmailProvider implements EmailProviderClient.
func (c *httpClient) AddSMTPEmailProvider(ctx context.Context, cfg SMTPProviderConfig) (string, error) {
	var resp struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/admin/v1/email/smtp", toSMTPProviderBody(cfg), &resp); err != nil {
		return "", fmt.Errorf("AddSMTPEmailProvider: %w", err)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("AddSMTPEmailProvider: empty id in response: %w", ErrUnreachable)
	}
	return resp.ID, nil
}

// UpdateSMTPEmailProvider implements EmailProviderClient.
func (c *httpClient) UpdateSMTPEmailProvider(ctx context.Context, id string, cfg SMTPProviderConfig) error {
	path := "/admin/v1/email/smtp/" + url.PathEscape(id)
	if err := c.doJSON(ctx, http.MethodPut, path, toSMTPProviderBody(cfg), nil); err != nil {
		return fmt.Errorf("UpdateSMTPEmailProvider id=%s: %w", id, err)
	}
	return nil
}

// ActivateEmailProvider implements EmailProviderClient.
func (c *httpClient) ActivateEmailProvider(ctx context.Context, id string) error {
	path := "/admin/v1/email/" + url.PathEscape(id) + "/_activate"
	if err := c.doJSON(ctx, http.MethodPost, path, struct{}{}, nil); err != nil {
		return fmt.Errorf("ActivateEmailProvider id=%s: %w", id, err)
	}
	return nil
}

// emailProviderSearchResult decodes one entry of ListEmailProviders'
// `result` array (proto EmailProvider). Only the fields this client actually
// consumes are declared — see the client.go package doc's protojson
// warning: nothing here maps a numeric proto field (e.g. details.sequence,
// a uint64 rendered as a JSON string) into a non-string Go type, so there is
// no int64/uint64 decode hazard even though the full EmailProvider message
// carries one.
type emailProviderSearchResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// FindSMTPEmailProviderByDescription implements EmailProviderClient.
func (c *httpClient) FindSMTPEmailProviderByDescription(ctx context.Context, description string) (string, error) {
	var resp struct {
		Result []emailProviderSearchResult `json:"result"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/admin/v1/email/_search", map[string]any{}, &resp); err != nil {
		return "", fmt.Errorf("FindSMTPEmailProviderByDescription: %w", err)
	}
	for _, p := range resp.Result {
		if p.Description == description {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf("FindSMTPEmailProviderByDescription %q: %w", description, ErrNotFound)
}

// emailProviderSMTPConfig decodes the "smtp" arm of EmailProvider.config
// (proto EmailProviderSMTP). Absent (nil) when the provider is an HTTP
// provider instead.
type emailProviderSMTPConfig struct {
	SenderAddress  string `json:"senderAddress"`
	SenderName     string `json:"senderName"`
	TLS            bool   `json:"tls"`
	Host           string `json:"host"`
	User           string `json:"user"`
	ReplyToAddress string `json:"replyToAddress"`
}

// toSMTPProviderState converts a decoded EmailProvider (id + state +
// optional smtp config) into the client's public SMTPProviderState. Shared
// by GetSMTPEmailProviderState (GetEmailProviderById) and
// IsSMTPProviderActive (GetEmailProvider) since both decode the same
// EmailProvider message shape, just reached via different endpoints.
func toSMTPProviderState(id, state string, smtp *emailProviderSMTPConfig) SMTPProviderState {
	out := SMTPProviderState{
		ID:     id,
		Active: state == "EMAIL_PROVIDER_ACTIVE",
		IsSMTP: smtp != nil,
	}
	if smtp != nil {
		out.SenderAddress = smtp.SenderAddress
		out.SenderName = smtp.SenderName
		out.TLS = smtp.TLS
		out.Host = smtp.Host
		out.User = smtp.User
		out.ReplyToAddress = smtp.ReplyToAddress
	}
	return out
}

// GetSMTPEmailProviderState implements EmailProviderClient.
func (c *httpClient) GetSMTPEmailProviderState(ctx context.Context, id string) (SMTPProviderState, error) {
	path := "/admin/v1/email/" + url.PathEscape(id)
	var resp struct {
		Config struct {
			ID    string                   `json:"id"`
			State string                   `json:"state"`
			SMTP  *emailProviderSMTPConfig `json:"smtp"`
		} `json:"config"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return SMTPProviderState{}, fmt.Errorf("GetSMTPEmailProviderState id=%s: %w", id, err)
	}
	return toSMTPProviderState(resp.Config.ID, resp.Config.State, resp.Config.SMTP), nil
}

// IsSMTPProviderActive implements EmailProviderClient.
func (c *httpClient) IsSMTPProviderActive(ctx context.Context) (bool, error) {
	var resp struct {
		Config struct {
			ID    string                   `json:"id"`
			State string                   `json:"state"`
			SMTP  *emailProviderSMTPConfig `json:"smtp"`
		} `json:"config"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/admin/v1/email", nil, &resp)
	if err != nil {
		if IsNotFound(err) {
			// No email provider configured at all — the exact hosted#189
			// starting state, not an error.
			return false, nil
		}
		return false, fmt.Errorf("IsSMTPProviderActive: %w", err)
	}
	state := toSMTPProviderState(resp.Config.ID, resp.Config.State, resp.Config.SMTP)
	return state.Active && state.IsSMTP, nil
}
