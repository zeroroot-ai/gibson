package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// MintUserPAT
// ---------------------------------------------------------------------------
//
// Idempotently ensures a Zitadel service user exists, optionally grants IAM
// roles, and returns a Personal Access Token (PAT) for that user.
//
// Caller invariants:
//
//   - The same username on repeated calls returns the SAME `user_id`; the
//     `pat` field is only fresh when `rotated=true`. Zitadel's PAT-list API
//     returns PAT IDs but never the secret token (it's only available on
//     creation), so re-emitting an existing PAT is impossible. If a PAT
//     already exists and `--rotate` was not passed, this returns an error.
//
//   - `--rotate` triggers minting a fresh PAT AND revoking every existing
//     active PAT for the user. Use this when the existing token has been
//     compromised or when bootstrap-secrets cycles credentials.

// MintUserPATRequest is the input shape for the zitadel-mint-user-pat
// subcommand.
type MintUserPATRequest struct {
	// Username is the service-user name (e.g. "gibson-signup-bot"). Required.
	Username string

	// Roles is the list of IAM role keys to grant to the service user
	// (e.g. ["IAM_USER_MANAGER"]). When empty, no roles are granted in this
	// call (but pre-existing role grants are preserved).
	Roles []string

	// Rotate forces minting a fresh PAT and revoking every prior active PAT.
	// Required when a PAT already exists for the user; passing false in that
	// case is an error (the PAT secret is not retrievable after creation).
	Rotate bool
}

// MintUserPATResult is the JSON output of zitadel-mint-user-pat.
type MintUserPATResult struct {
	UserID  string `json:"user_id"`
	PAT     string `json:"pat"`
	Rotated bool   `json:"rotated"`
}

// MintUserPAT ensures the service user, grants roles, and returns a PAT.
func (c *patClient) MintUserPAT(ctx context.Context, req MintUserPATRequest) (*MintUserPATResult, error) {
	if strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}

	slog.Info("ensuring service user", "username", req.Username)

	userID, err := c.ensureServiceUser(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("ensure service user: %w", err)
	}

	if len(req.Roles) > 0 {
		if err := c.assignIAMRoles(ctx, userID, req.Roles); err != nil {
			return nil, fmt.Errorf("assign IAM roles: %w", err)
		}
	}

	// Inventory existing PATs.
	activePATs, err := c.listActivePATs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list PATs: %w", err)
	}

	switch {
	case len(activePATs) == 0:
		// First-time bootstrap: mint clean.
		token, err := c.mintPAT(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("mint PAT: %w", err)
		}
		return &MintUserPATResult{UserID: userID, PAT: token, Rotated: true}, nil

	case req.Rotate:
		// Mint first, then revoke prior — keeps the user with at least one
		// valid PAT throughout the rotation in case anything observes.
		token, err := c.mintPAT(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("mint PAT: %w", err)
		}
		for _, oldID := range activePATs {
			if err := c.revokePAT(ctx, userID, oldID); err != nil {
				// Soft-warn rather than fail — the new PAT is already valid.
				slog.Warn("revoke prior PAT failed", "pat_id", oldID, "err", err)
			}
		}
		return &MintUserPATResult{UserID: userID, PAT: token, Rotated: true}, nil

	default:
		// PAT already exists; without --rotate we cannot return its secret.
		return nil, fmt.Errorf(
			"service user %q already has %d active PAT(s); pass --rotate to mint a fresh one (Zitadel's list API does not return PAT secrets)",
			req.Username, len(activePATs),
		)
	}
}

// ensureServiceUser idempotently creates a Zitadel service user with the
// given username and returns its user_id. Existing users with the same
// username are returned with no mutation.
func (c *patClient) ensureServiceUser(ctx context.Context, username string) (string, error) {
	// Search first — cheap idempotency.
	type userNameQuery struct {
		UserName string `json:"userName"`
		Method   string `json:"method"`
	}
	type userQuery struct {
		UserNameQuery userNameQuery `json:"userNameQuery"`
	}
	searchBody := map[string]interface{}{
		"queries": []userQuery{{UserNameQuery: userNameQuery{
			UserName: username,
			Method:   "TEXT_QUERY_METHOD_EQUALS",
		}}},
	}

	var searchResp struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/_search", "", searchBody, &searchResp); err != nil {
		return "", fmt.Errorf("search users: %w", err)
	}
	if len(searchResp.Result) == 1 {
		return searchResp.Result[0].ID, nil
	}
	if len(searchResp.Result) > 1 {
		return "", fmt.Errorf("ambiguous username %q: %d matching service users", username, len(searchResp.Result))
	}

	// Create.
	createBody := map[string]interface{}{
		"userName": username,
		"name":     username,
	}
	var createResp struct {
		UserID string `json:"userId"`
	}
	if err := c.doRequest(ctx, http.MethodPost, "/management/v1/users/machine", "", createBody, &createResp); err != nil {
		// Conflict (409) means a concurrent creator beat us; re-search.
		if isConflict(err) {
			var searchResp2 struct {
				Result []struct {
					ID string `json:"id"`
				} `json:"result"`
			}
			if err2 := c.doRequest(ctx, http.MethodPost, "/management/v1/users/_search", "", searchBody, &searchResp2); err2 != nil {
				return "", fmt.Errorf("re-search users after create-conflict: %w", err2)
			}
			if len(searchResp2.Result) == 1 {
				return searchResp2.Result[0].ID, nil
			}
		}
		return "", fmt.Errorf("create service user: %w", err)
	}
	return createResp.UserID, nil
}

// assignIAMRoles grants each role in `roles` to the user at the IAM level.
// Existing grants are preserved (Zitadel returns ALREADY_EXISTS on duplicate
// grants which this code treats as success).
func (c *patClient) assignIAMRoles(ctx context.Context, userID string, roles []string) error {
	for _, role := range roles {
		body := map[string]interface{}{
			"userId": userID,
			"roles":  []string{role},
		}
		var resp map[string]interface{}
		err := c.doRequest(ctx, http.MethodPost, "/admin/v1/members", "", body, &resp)
		if err != nil && !isConflict(err) {
			return fmt.Errorf("grant role %q: %w", role, err)
		}
	}
	return nil
}

// listActivePATs returns the IDs of every active PAT for the given user.
// Zitadel's API does NOT return the token secrets — only the IDs are useful
// (for revocation).
func (c *patClient) listActivePATs(ctx context.Context, userID string) ([]string, error) {
	path := fmt.Sprintf("/management/v1/users/%s/pats/_search", userID)
	body := map[string]interface{}{}

	var resp struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := c.doRequest(ctx, http.MethodPost, path, "", body, &resp); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(resp.Result))
	for _, r := range resp.Result {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// mintPAT creates a fresh PAT for the user and returns the secret token.
// The token can only be retrieved on creation — it's never returned by the
// list / get APIs again.
func (c *patClient) mintPAT(ctx context.Context, userID string) (string, error) {
	path := fmt.Sprintf("/management/v1/users/%s/pats", userID)
	// No expirationDate — keep tokens long-lived for dev/bootstrap. Operators
	// can configure expiry via overlays when needed.
	body := map[string]interface{}{}

	var resp struct {
		Token string `json:"token"`
	}
	if err := c.doRequest(ctx, http.MethodPost, path, "", body, &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", errors.New("mintPAT: empty token in response")
	}
	return resp.Token, nil
}

// revokePAT revokes a single PAT by ID.
func (c *patClient) revokePAT(ctx context.Context, userID, patID string) error {
	path := fmt.Sprintf("/management/v1/users/%s/pats/%s", userID, patID)
	return c.doRequest(ctx, http.MethodDelete, path, "", nil, nil)
}
