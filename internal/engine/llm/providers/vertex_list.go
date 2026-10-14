// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// vertexTokenFunc mints an OAuth access token for the Vertex API. The client
// carries the token request, so it goes through the same SSRF guard.
type vertexTokenFunc func(ctx context.Context, client *http.Client) (string, error)

// googleAccessToken mints a cloud-platform access token from the Application
// Default Credentials, the way the Vertex Claude client reads them (see
// NewVertexProvider).
func googleAccessToken(ctx context.Context, client *http.Client) (string, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", fmt.Errorf("find the google application default credentials: %w", err)
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("mint the google access token: %w", err)
	}
	return tok.AccessToken, nil
}

// vertexListBase returns the API host for the region. The list is not scoped to
// a project or a region, so the region only picks the host. "global" uses the
// apex host.
func vertexListBase(override, region string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	if region == "" || region == "global" {
		return "https://aiplatform.googleapis.com"
	}
	return "https://" + region + "-aiplatform.googleapis.com"
}

// listVertexModels lists the Anthropic publisher models with
// GET {base}/v1beta1/publishers/anthropic/models. The method exists in v1beta1
// only. See
// https://docs.cloud.google.com/vertex-ai/docs/reference/rest/v1beta1/publishers.models/list
// The response is {"publisherModels":[{"name":"publishers/anthropic/models/<id>"}],
// "nextPageToken":".."}. The list names the models of the publisher. It does not
// show which models the project has enabled in Model Garden.
func listVertexModels(ctx context.Context, client *http.Client, base string, token vertexTokenFunc) ([]llm.ModelInfo, error) {
	provider := string(llm.ProviderVertex)
	access, err := token(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("vertex credential: %w", llm.NewAuthError(provider, err))
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+access)

	var models []llm.ModelInfo
	pageToken := ""
	for range maxModelListPages {
		q := url.Values{"pageSize": {"100"}}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var page struct {
			PublisherModels []struct {
				Name string `json:"name"`
			} `json:"publisherModels"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := getJSON(ctx, client, provider, base+"/v1beta1/publishers/anthropic/models?"+q.Encode(), header, &page); err != nil {
			return nil, err
		}
		for _, m := range page.PublisherModels {
			if id := path.Base(m.Name); id != "" && id != "." && id != "/" {
				models = append(models, llm.ModelInfo{Name: id, Features: []string{"chat"}})
			}
		}
		if page.NextPageToken == "" || page.NextPageToken == pageToken {
			return models, nil
		}
		pageToken = page.NextPageToken
	}
	return models, nil
}
