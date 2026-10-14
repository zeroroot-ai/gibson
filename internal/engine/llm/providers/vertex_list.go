// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// vertexTokenFunc mints an OAuth access token for the Vertex API from the
// service-account JSON that the tenant entered. The client carries the token
// request, so it goes through the same SSRF guard.
type vertexTokenFunc func(ctx context.Context, client *http.Client, serviceAccountJSON string) (string, error)

// serviceAccountToken mints a cloud-platform access token from the tenant's
// service-account JSON. It reads nothing else: the Application Default
// Credentials of the daemon are never used, so the result says whether THIS
// tenant credential works. Only a service-account key is accepted. Other
// credential types (external account, authorized user) can make the Google
// library fetch a URL that the key names.
func serviceAccountToken(ctx context.Context, client *http.Client, serviceAccountJSON string) (string, error) {
	if strings.TrimSpace(serviceAccountJSON) == "" {
		return "", errors.New("google_application_credentials_json is empty")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	creds, err := google.CredentialsFromJSONWithType(ctx, []byte(serviceAccountJSON), google.ServiceAccount,
		"https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", fmt.Errorf("read the service-account JSON: %w", err)
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
// show which models the project has enabled in Model Garden. The tenant's project
// goes in x-goog-user-project, so the call succeeds only for a credential that
// may use that project.
func listVertexModels(ctx context.Context, client *http.Client, base, project, serviceAccountJSON string, token vertexTokenFunc) ([]llm.ModelInfo, error) {
	provider := string(llm.ProviderVertex)
	access, err := token(ctx, client, serviceAccountJSON)
	if err != nil {
		return nil, fmt.Errorf("vertex credential: %w", llm.NewAuthError(provider, err))
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+access)
	// The call is billed to the tenant's project. It therefore fails unless the
	// credential may use that project and the Vertex API is on there.
	header.Set("x-goog-user-project", project)

	var models []llm.ModelInfo
	pageToken := ""
	for range maxModelListPages {
		q := url.Values{"pageSize": {"100"}}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var page struct {
			PublisherModels []struct {
				Name      string `json:"name"`
				VersionID string `json:"versionId"`
			} `json:"publisherModels"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := getJSON(ctx, client, provider, base+"/v1beta1/publishers/anthropic/models?"+q.Encode(), header, &page); err != nil {
			return nil, err
		}
		for _, m := range page.PublisherModels {
			if id := vertexModelID(m.Name, m.VersionID); id != "" {
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

// vertexModelID turns a publisher model name and version into the ID that a
// completion call takes: model@version, the form that Google documents for
// Claude on Vertex (see
// https://docs.cloud.google.com/vertex-ai/generative-ai/docs/partner-models/claude/use-claude).
// A model with no version is returned bare.
func vertexModelID(name, versionID string) string {
	id := path.Base(name)
	if id == "" || id == "." || id == "/" {
		return ""
	}
	if versionID == "" || versionID == "default" || strings.Contains(id, "@") {
		return id
	}
	return id + "@" + versionID
}
