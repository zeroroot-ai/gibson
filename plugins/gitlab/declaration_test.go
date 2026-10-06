// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/sdk/plugin/secrets"
)

// The declaration in code names the plugin and its version, and registers one
// handler per method (ADR-0097).
func TestServeOptions_DeclareThePlugin(t *testing.T) {
	if pluginName != "gitlab" || pluginVersion == "" {
		t.Fatalf("declaration = %q %q", pluginName, pluginVersion)
	}
	if got := len(serveOptions()); got != 6 {
		t.Fatalf("serveOptions returns %d options, want name, version, 3 handlers and the lifecycle", got)
	}
}

// deniedSecrets refuses every resolve, the state of a plugin whose tenant
// admin granted no secret.
type deniedSecrets struct{ secrets.Client }

func (deniedSecrets) Resolve(context.Context, string, ...secrets.Option) ([]byte, error) {
	return nil, secrets.ErrPermissionDenied
}

type grantedSecrets struct{ secrets.Client }

func (grantedSecrets) Resolve(context.Context, string, ...secrets.Option) ([]byte, error) {
	return []byte("token"), nil
}

// A plugin with no grant on its token fails at boot with the secret named.
func TestRequireToken_NamesTheSecretWhenNotGranted(t *testing.T) {
	err := requireToken(secrets.NewContext(context.Background(), deniedSecrets{}))
	if err == nil || !strings.Contains(err.Error(), credName) || !errors.Is(err, secrets.ErrPermissionDenied) {
		t.Fatalf("requireToken = %v, want an error that names %s", err, credName)
	}
	if err := requireToken(secrets.NewContext(context.Background(), grantedSecrets{})); err != nil {
		t.Fatalf("requireToken with a grant = %v, want nil", err)
	}
}
