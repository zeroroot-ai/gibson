// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
)

// LabelSlot is one brand-mark slot of the instance label policy.
type LabelSlot struct {
	// Field is the policy field that holds the URL of the served mark.
	Field string
	// Upload is the asset path that replaces the mark on the preview policy.
	Upload string
	// Remove is the admin path that clears the mark on the preview policy.
	Remove string
}

// LabelSlots are the four mark slots, in the order the reconciler visits
// them. The login pages read the dark slots in dark mode.
var LabelSlots = []LabelSlot{
	{Field: "logoUrl", Upload: "/assets/v1/instance/policy/label/logo", Remove: "/admin/v1/policies/label/logo"},
	{Field: "logoUrlDark", Upload: "/assets/v1/instance/policy/label/logo/dark", Remove: "/admin/v1/policies/label/logo_dark"},
	{Field: "iconUrl", Upload: "/assets/v1/instance/policy/label/icon", Remove: "/admin/v1/policies/label/icon"},
	{Field: "iconUrlDark", Upload: "/assets/v1/instance/policy/label/icon/dark", Remove: "/admin/v1/policies/label/icon_dark"},
}

// LabelPolicyClient is the instance label policy surface.
//
// Zitadel keeps two copies of the policy: the preview, which every write
// changes, and the active policy, which the login pages serve. A write
// reaches the login pages only after ActivateLabelPolicy.
type LabelPolicyClient interface {
	// GetLabelPolicy returns the active instance label policy, keyed by the
	// admin API's JSON field names.
	GetLabelPolicy(ctx context.Context) (map[string]any, error)

	// UpdateLabelPolicy writes policy to the preview. Zitadel answers 400
	// when the preview already holds these values; that error wraps
	// ErrInvalidInput.
	UpdateLabelPolicy(ctx context.Context, policy map[string]any) error

	// LabelAsset returns the bytes Zitadel serves at a mark URL from the
	// active policy. The URL names the public host; the client fetches its
	// path from its own base URL.
	LabelAsset(ctx context.Context, assetURL string) ([]byte, error)

	// RemoveLabelAsset clears one slot on the preview. An empty slot is
	// success.
	RemoveLabelAsset(ctx context.Context, slot LabelSlot) error

	// UploadLabelAsset puts an SVG mark into one slot on the preview.
	UploadLabelAsset(ctx context.Context, slot LabelSlot, svg []byte) error

	// ActivateLabelPolicy makes the preview the active policy. An already
	// active preview is success.
	ActivateLabelPolicy(ctx context.Context) error
}

// GetLabelPolicy implements LabelPolicyClient.
func (c *httpClient) GetLabelPolicy(ctx context.Context) (map[string]any, error) {
	var out struct {
		Policy map[string]any `json:"policy"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/admin/v1/policies/label", nil, &out); err != nil {
		return nil, fmt.Errorf("get label policy: %w", err)
	}
	if out.Policy == nil {
		return nil, fmt.Errorf("get label policy: the response has no policy: %w", ErrUnreachable)
	}
	return out.Policy, nil
}

// UpdateLabelPolicy implements LabelPolicyClient.
func (c *httpClient) UpdateLabelPolicy(ctx context.Context, policy map[string]any) error {
	if err := c.doJSON(ctx, http.MethodPut, "/admin/v1/policies/label", policy, nil); err != nil {
		return fmt.Errorf("update label policy: %w", err)
	}
	return nil
}

// LabelAsset implements LabelPolicyClient.
func (c *httpClient) LabelAsset(ctx context.Context, assetURL string) ([]byte, error) {
	u, err := url.Parse(assetURL)
	if err != nil || u.Path == "" {
		return nil, fmt.Errorf("label asset %q: not a URL: %w", assetURL, ErrInvalidInput)
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	status, body, err := c.doRaw(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(http.MethodGet, u.Path, status, body)
	}
	return body, nil
}

// RemoveLabelAsset implements LabelPolicyClient.
func (c *httpClient) RemoveLabelAsset(ctx context.Context, slot LabelSlot) error {
	status, body, err := c.doRaw(ctx, http.MethodDelete, slot.Remove, "", nil)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300, status == http.StatusNotFound, status == http.StatusPreconditionFailed:
		// 404 and 412: the slot is already empty.
		return nil
	default:
		return statusError(http.MethodDelete, slot.Remove, status, body)
	}
}

// UploadLabelAsset implements LabelPolicyClient.
func (c *httpClient) UploadLabelAsset(ctx context.Context, slot LabelSlot, svg []byte) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="file"; filename="mark.svg"`)
	h.Set("Content-Type", "image/svg+xml")
	part, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("upload %s: %w", slot.Upload, err)
	}
	if _, err := part.Write(svg); err != nil {
		return fmt.Errorf("upload %s: %w", slot.Upload, err)
	}
	if err := mw.Close(); err != nil {
		return fmt.Errorf("upload %s: %w", slot.Upload, err)
	}
	status, body, err := c.doRaw(ctx, http.MethodPost, slot.Upload, mw.FormDataContentType(), &buf)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return statusError(http.MethodPost, slot.Upload, status, body)
	}
	return nil
}

// ActivateLabelPolicy implements LabelPolicyClient.
func (c *httpClient) ActivateLabelPolicy(ctx context.Context) error {
	err := c.doJSON(ctx, http.MethodPost, "/admin/v1/policies/label/_activate", map[string]any{}, nil)
	if err == nil || errors.Is(err, ErrAlreadyExists) {
		// 409: the preview is already the active policy.
		return nil
	}
	return fmt.Errorf("activate label policy: %w", err)
}

// doRaw sends one request with the client's auth and host, and returns the
// status and body. Only a transport failure is an error.
func (c *httpClient) doRaw(ctx context.Context, method, path, contentType string, body io.Reader) (int, []byte, error) {
	full, err := c.baseURL.Parse(path)
	if err != nil {
		return 0, nil, fmt.Errorf("zitadel: path %q: %w", path, ErrInvalidInput)
	}
	req, err := http.NewRequestWithContext(ctx, method, full.String(), body)
	if err != nil {
		return 0, nil, fmt.Errorf("zitadel: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.pat)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.externalDomain != "" {
		req.Host = c.externalDomain
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("zitadel: %v: %w", err, ErrUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("zitadel: read %s %s: %v: %w", method, path, err, ErrUnreachable)
	}
	return resp.StatusCode, raw, nil
}

// statusError maps a non-success status the way doJSON does.
func statusError(method, path string, status int, raw []byte) error {
	switch {
	case status == http.StatusNotFound:
		return fmt.Errorf("zitadel %s %s 404: %w", method, path, ErrNotFound)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return WrapPermanent(fmt.Errorf("zitadel %s %s %d: %w: %s", method, path, status, ErrUnauthorized, raw))
	case status == http.StatusTooManyRequests:
		return fmt.Errorf("zitadel %s %s %d: %w", method, path, status, ErrRateLimited)
	case status >= 400 && status < 500:
		return fmt.Errorf("zitadel %s %s %d: %w: %s", method, path, status, ErrInvalidInput, raw)
	default:
		return fmt.Errorf("zitadel %s %s %d: %w: %s", method, path, status, ErrUnreachable, raw)
	}
}

func (e *errClient) GetLabelPolicy(context.Context) (map[string]any, error)  { return nil, e.err }
func (e *errClient) UpdateLabelPolicy(context.Context, map[string]any) error { return e.err }
func (e *errClient) LabelAsset(context.Context, string) ([]byte, error)      { return nil, e.err }
func (e *errClient) RemoveLabelAsset(context.Context, LabelSlot) error       { return e.err }
func (e *errClient) UploadLabelAsset(context.Context, LabelSlot, []byte) error {
	return e.err
}
func (e *errClient) ActivateLabelPolicy(context.Context) error { return e.err }
