// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package provision

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type failingOAuth2Source struct{}

func (failingOAuth2Source) Token() (*oauth2.Token, error) {
	return nil, errors.New("token endpoint refused")
}

// TestOAuth2TokenSource_ReturnsTheAccessToken proves FetchToken returns the
// access token of the wrapped source and ignores the audience.
func TestOAuth2TokenSource_ReturnsTheAccessToken(t *testing.T) {
	src := &OAuth2TokenSource{Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "jwt-1"})}
	got, err := src.FetchToken(context.Background(), "gibson-daemon")
	if err != nil {
		t.Fatalf("FetchToken: %v", err)
	}
	if got != "jwt-1" {
		t.Fatalf("FetchToken = %q, want jwt-1", got)
	}
}

// TestOAuth2TokenSource_WrapsTheSourceError proves a failed token request
// returns an error that names the token source.
func TestOAuth2TokenSource_WrapsTheSourceError(t *testing.T) {
	src := &OAuth2TokenSource{Source: failingOAuth2Source{}}
	_, err := src.FetchToken(context.Background(), "gibson-daemon")
	if err == nil || !strings.Contains(err.Error(), "OAuth2TokenSource: token endpoint refused") {
		t.Fatalf("FetchToken error = %v, want the wrapped source error", err)
	}
}
