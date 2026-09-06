// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrNoGrant reports that a connector has no stored grant. The refresher loop
// treats it as "nothing to refresh" rather than a failure: a registered
// connector that has never been authorized is a normal state, surfaced to the
// operator by the status RPC rather than by log noise.
var ErrNoGrant = errors.New("connectorauth: no grant stored")

// SecretStore is the slice of the platform secrets service this package needs.
// Narrow on purpose: the refresher reads and writes three names and does
// nothing else with the broker.
type SecretStore interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
	Put(ctx context.Context, name string, value []byte) error
}

// Refresher mints a connector's access token from its grant and publishes it.
//
// It never runs an interactive OAuth flow. Authorization is a human act that
// happens once, in the operator's browser, against the customer's own vendor
// instance (ADR-0064) — this only exercises the refresh_token grant, which is
// machine-to-machine.
type Refresher struct {
	store  SecretStore
	client *http.Client
	now    func() time.Time

	// skew is how far before real expiry a token is treated as expired. A
	// token that expires while in flight is indistinguishable from a revoked
	// one at the vendor, and the connector cannot tell the difference either.
	skew time.Duration
}

// RefresherOption configures a Refresher.
type RefresherOption func(*Refresher)

// WithSkew overrides how far before real expiry a token counts as expired.
// The background loop sets this to comfortably more than its tick interval,
// so a token is always renewed at least one full interval before it dies.
func WithSkew(d time.Duration) RefresherOption {
	return func(r *Refresher) {
		if d > 0 {
			r.skew = d
		}
	}
}

// NewRefresher constructs a Refresher. client and now may be nil.
func NewRefresher(store SecretStore, client *http.Client, now func() time.Time, opts ...RefresherOption) (*Refresher, error) {
	if store == nil {
		return nil, errors.New("connectorauth: secret store must not be nil")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	r := &Refresher{store: store, client: client, now: now, skew: 60 * time.Second}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// tokenResponse is the subset of RFC 6749 §5.1 this package acts on.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// Refresh exchanges a connector's refresh token for a new access token, writes
// the access token to its own secret, and persists a rotated refresh token
// back to the grant.
//
// The rotation write is the part that cannot be skipped. OAuth 2.1 issues a
// NEW refresh token on every refresh and invalidates the old one, so failing
// to persist it leaves the stored grant dead — the connector works until the
// next restart and then never again. That is precisely the failure a
// bridge-owned token could not avoid, and the reason this lives here.
func (r *Refresher) Refresh(ctx context.Context, connector string) (*AccessToken, error) {
	grant, err := r.loadGrant(ctx, connector)
	if err != nil {
		return nil, err
	}
	return r.refreshGrant(ctx, connector, grant)
}

// refreshGrant exercises the refresh_token grant against the vendor and
// publishes the access pair. A static grant has nothing to exercise and is
// refused: the caller (EnsureFresh) skips it, and a direct Refresh on one is a
// programming error surfaced as such rather than a vendor call with an empty
// refresh token.
func (r *Refresher) refreshGrant(ctx context.Context, connector string, grant *Grant) (*AccessToken, error) {
	grantName := GrantSecretName(connector)
	if grant.Static {
		return nil, fmt.Errorf("connectorauth: connector %q holds a static credential; nothing to refresh", connector)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {grant.RefreshToken},
		"client_id":     {grant.ClientID},
	}
	if grant.ClientSecret != "" {
		form.Set("client_secret", grant.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, grant.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("connectorauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		// The URL can carry no credential — the token travels in the body —
		// but wrapping the raw error would leak the endpoint into logs at
		// every retry, so name the connector instead.
		return nil, fmt.Errorf("connectorauth: token endpoint unreachable for connector %q", connector)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("connectorauth: read token response for connector %q", connector)
	}
	if resp.StatusCode != http.StatusOK {
		// The body of an OAuth error is an error code, not a credential, and
		// it is the only thing that distinguishes "revoked" from "misconfigured
		// client" — an operator cannot act without it.
		return nil, fmt.Errorf("connectorauth: connector %q token refresh refused (%d): %s",
			connector, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("connectorauth: connector %q token response is not valid JSON", connector)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("connectorauth: connector %q token response carried no access_token", connector)
	}

	// Persist a rotated refresh token BEFORE publishing the access token. If
	// the process dies between the two, the grant is still the live one and
	// the next refresh succeeds. The other order would strand a grant whose
	// refresh token the vendor has already invalidated.
	if tr.RefreshToken != "" && tr.RefreshToken != grant.RefreshToken {
		rotated := *grant
		rotated.RefreshToken = tr.RefreshToken
		blob, err := MarshalGrant(&rotated)
		if err != nil {
			return nil, fmt.Errorf("connectorauth: connector %q rotated grant: %w", connector, err)
		}
		if err := r.store.Put(ctx, grantName, blob); err != nil {
			return nil, fmt.Errorf("connectorauth: connector %q persist rotated grant: %w", connector, err)
		}
	}

	expiresAt := r.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.ExpiresIn == 0 {
		// A vendor that omits expires_in has not said the token is eternal.
		// Treat it as short-lived so the refresher keeps running rather than
		// pinning a token forever.
		expiresAt = r.now().Add(time.Hour)
	}

	token := &AccessToken{Token: tr.AccessToken, ExpiresAt: expiresAt}

	// The connector-visible secret holds the RAW token: the bridge presents
	// the resolved bytes verbatim as `Authorization: Bearer <bytes>`, so any
	// wrapper would reach the vendor as a malformed credential. The expiry is
	// platform bookkeeping and goes to a separate platform-only secret,
	// written AFTER the token: if the process dies between the two writes,
	// stale metadata makes the next pass refresh again (harmless), where the
	// other order would schedule against a token that was never published.
	if err := r.store.Put(ctx, AccessSecretName(connector), []byte(tr.AccessToken)); err != nil {
		return nil, fmt.Errorf("connectorauth: connector %q publish access token: %w", connector, err)
	}
	meta, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("connectorauth: connector %q marshal access metadata: %w", connector, err)
	}
	if err := r.store.Put(ctx, AccessMetaSecretName(connector), meta); err != nil {
		return nil, fmt.Errorf("connectorauth: connector %q record access expiry: %w", connector, err)
	}
	return token, nil
}

// NeedsRefresh reports whether a connector's published access token is absent,
// unreadable or close enough to expiry to be treated as expired.
//
// An unreadable state is deliberately "needs refresh" rather than an error:
// the recovery for a corrupt or half-written token is to mint another one, and
// the grant is what proves whether that is possible.
func (r *Refresher) NeedsRefresh(ctx context.Context, connector string) bool {
	raw, err := r.store.Resolve(ctx, AccessSecretName(connector))
	if err != nil || len(raw) == 0 {
		return true
	}
	meta, err := r.store.Resolve(ctx, AccessMetaSecretName(connector))
	if err != nil || len(meta) == 0 {
		return true
	}
	var tok AccessToken
	if err := json.Unmarshal(meta, &tok); err != nil {
		return true
	}
	return !r.now().Add(r.skew).Before(tok.ExpiresAt)
}

// EnsureFresh refreshes only when needed and returns whether it did.
//
// A static grant (a customer-supplied credential, ADR-0015) is never
// refreshed: there is no refresh token and no expiry the platform manages,
// so the access secret stays as the tenant admin set it.
func (r *Refresher) EnsureFresh(ctx context.Context, connector string) (refreshed bool, err error) {
	if !r.NeedsRefresh(ctx, connector) {
		return false, nil
	}
	grant, err := r.loadGrant(ctx, connector)
	if err != nil {
		return false, err
	}
	if grant.Static {
		return false, nil
	}
	if _, err := r.refreshGrant(ctx, connector, grant); err != nil {
		return false, err
	}
	return true, nil
}

// loadGrant reads and validates a connector's stored grant. An absent grant
// is ErrNoGrant, so callers can tell "nobody authorized this" from a broker
// failure.
func (r *Refresher) loadGrant(ctx context.Context, connector string) (*Grant, error) {
	grantName := GrantSecretName(connector)
	raw, err := r.store.Resolve(ctx, grantName)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("connector %q: %w", connector, ErrNoGrant)
		}
		return nil, fmt.Errorf("connectorauth: resolve grant %q: %w", grantName, err)
	}
	grant, err := UnmarshalGrant(raw)
	if err != nil {
		return nil, fmt.Errorf("connectorauth: grant %q: %w", grantName, err)
	}
	return grant, nil
}
