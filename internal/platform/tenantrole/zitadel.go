// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantrole

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// Sentinel errors a Grants implementation maps a Connect error code onto.
// ErrRejected and ErrUnauthorized are permanent: retrying the identical
// request cannot succeed. ErrUnreachable is transient.
var (
	ErrNotFound      = errors.New("tenantrole: not found")
	ErrAlreadyExists = errors.New("tenantrole: already exists")
	ErrRejected      = errors.New("tenantrole: rejected")
	ErrUnauthorized  = errors.New("tenantrole: unauthorized")
	ErrUnreachable   = errors.New("tenantrole: unreachable")
)

// Grant is one Zitadel authorization on the gibson project.
type Grant struct {
	ID        string
	UserID    string
	UserOrgID string // the org the user belongs to
	OrgID     string // the org the grant belongs to
	RoleKeys  []string
	Active    bool
}

// Grants is the Zitadel side of a tenant role: the v2 AuthorizationService
// calls a Syncer needs to read and write one person's role grant.
type Grants interface {
	// List returns every grant on the project in orgID. When userIDs is
	// non-empty, it returns only the grants of those users. It pages
	// through every result.
	List(ctx context.Context, orgID string, userIDs []string) ([]Grant, error)
	// Create makes a new grant for userID in orgID with role r and returns
	// its id.
	Create(ctx context.Context, orgID, userID string, r Role) (string, error)
	// Update replaces grantID's role keys with the single key for r.
	Update(ctx context.Context, grantID string, r Role) error
	// Delete removes grantID. An absent id is success.
	Delete(ctx context.Context, grantID string) error
}

const (
	projectService       = "zitadel.project.v2.ProjectService"
	authorizationService = "zitadel.authorization.v2.AuthorizationService"

	listGrantsPageSize = 500
)

type zitadelGrants struct {
	ep        zitadelconn.Endpoint
	hc        *http.Client
	projectID string
}

// NewZitadelGrants builds a Grants over an HTTP client that already carries
// the instance header and the bearer token (ADR-0092). Callers build hc from
// their own credential source: the daemon uses oauth2/clientcredentials over
// ep.Transport, the tenant-operator uses its Zitadel PAT.
func NewZitadelGrants(ep zitadelconn.Endpoint, hc *http.Client, projectID string) Grants {
	return &zitadelGrants{ep: ep, hc: hc, projectID: projectID}
}

func (g *zitadelGrants) connectJSON(ctx context.Context, service, method string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("tenantrole: marshal %s/%s body: %w", service, method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.ep.URL("/"+service+"/"+method), bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("tenantrole: new request %s/%s: %w", service, method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s/%s: %w", ErrUnreachable, service, method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("tenantrole: decode %s/%s: %w", service, method, err)
		}
		return nil
	}
	return mapConnectError(service, method, resp.StatusCode, raw)
}

// connectErrorBody is the Connect JSON error shape: {"code","message"}.
type connectErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func mapConnectError(service, method string, status int, raw []byte) error {
	var body connectErrorBody
	_ = json.Unmarshal(raw, &body)
	wrapped := func(sentinel error) error {
		return fmt.Errorf("%w: %s/%s: %d %s", sentinel, service, method, status, string(raw))
	}
	switch body.Code {
	case "not_found":
		return wrapped(ErrNotFound)
	case "already_exists":
		return wrapped(ErrAlreadyExists)
	case "failed_precondition", "invalid_argument":
		return wrapped(ErrRejected)
	case "unauthenticated", "permission_denied":
		return wrapped(ErrUnauthorized)
	case "unavailable", "deadline_exceeded":
		return wrapped(ErrUnreachable)
	}
	// The Connect code was missing or unrecognized: fall back to the HTTP
	// status, since every real Connect deployment still answers with the
	// matching status code (see section 2's status table).
	switch {
	case status == http.StatusNotFound:
		return wrapped(ErrNotFound)
	case status == http.StatusConflict:
		return wrapped(ErrAlreadyExists)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return wrapped(ErrUnauthorized)
	case status >= 400 && status < 500:
		return wrapped(ErrRejected)
	default:
		return wrapped(ErrUnreachable)
	}
}

func (g *zitadelGrants) List(ctx context.Context, orgID string, userIDs []string) ([]Grant, error) {
	filters := []map[string]any{
		{"organizationId": map[string]string{"id": orgID}},
		{"projectId": map[string]string{"id": g.projectID}},
	}
	if len(userIDs) > 0 {
		filters = append(filters, map[string]any{"inUserIds": map[string][]string{"ids": userIDs}})
	}

	type roleOut struct {
		Key string `json:"key"`
	}
	type idOut struct {
		ID string `json:"id"`
	}
	type authOut struct {
		ID      string `json:"id"`
		Project struct {
			ID             string `json:"id"`
			OrganizationID string `json:"organizationId"`
		} `json:"project"`
		Organization idOut `json:"organization"`
		User         struct {
			ID             string `json:"id"`
			OrganizationID string `json:"organizationId"`
		} `json:"user"`
		State string    `json:"state"`
		Roles []roleOut `json:"roles"`
	}
	type listResp struct {
		Authorizations []authOut `json:"authorizations"`
		Pagination     struct {
			TotalResult int `json:"totalResult"`
		} `json:"pagination"`
	}

	var out []Grant
	offset := 0
	for {
		var resp listResp
		body := map[string]any{
			"pagination": map[string]any{"offset": offset, "limit": listGrantsPageSize},
			"filters":    filters,
		}
		if err := g.connectJSON(ctx, authorizationService, "ListAuthorizations", body, &resp); err != nil {
			return nil, fmt.Errorf("tenantrole: List org=%s: %w", orgID, err)
		}
		for _, a := range resp.Authorizations {
			keys := make([]string, 0, len(a.Roles))
			for _, r := range a.Roles {
				keys = append(keys, r.Key)
			}
			out = append(out, Grant{
				ID: a.ID, UserID: a.User.ID, UserOrgID: a.User.OrganizationID,
				OrgID: a.Organization.ID, RoleKeys: keys, Active: a.State == "STATE_ACTIVE",
			})
		}
		offset += len(resp.Authorizations)
		if len(resp.Authorizations) == 0 || offset >= resp.Pagination.TotalResult {
			break
		}
	}
	return out, nil
}

func (g *zitadelGrants) Create(ctx context.Context, orgID, userID string, r Role) (string, error) {
	var resp struct {
		ID string `json:"id"`
	}
	body := map[string]any{
		"userId": userID, "projectId": g.projectID, "organizationId": orgID,
		"roleKeys": []string{string(r)},
	}
	if err := g.connectJSON(ctx, authorizationService, "CreateAuthorization", body, &resp); err != nil {
		return "", fmt.Errorf("tenantrole: Create org=%s user=%s role=%s: %w", orgID, userID, r, err)
	}
	return resp.ID, nil
}

func (g *zitadelGrants) Update(ctx context.Context, grantID string, r Role) error {
	body := map[string]any{"id": grantID, "roleKeys": []string{string(r)}}
	if err := g.connectJSON(ctx, authorizationService, "UpdateAuthorization", body, nil); err != nil {
		return fmt.Errorf("tenantrole: Update id=%s role=%s: %w", grantID, r, err)
	}
	return nil
}

func (g *zitadelGrants) Delete(ctx context.Context, grantID string) error {
	body := map[string]any{"id": grantID}
	if err := g.connectJSON(ctx, authorizationService, "DeleteAuthorization", body, nil); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("tenantrole: Delete id=%s: %w", grantID, err)
	}
	return nil
}
