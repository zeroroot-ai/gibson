// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/adk/gibson/cmd/gibson/cmd/secret"
	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// This file is step 4 of the SecretsService cutover (ADR-0058): the
// `gibson secret` commands of the adk CLI run against the server code that
// the daemon registers for gibson.secrets.v1.SecretsService.
//
// The server is the same CombinedSecretsServer that grpc.go registers, with
// the real SecretsAdminServer and TenantAdminServer behind it. Only the
// backends are in memory: the broker store, the audit sinks and the broker
// config store. An interceptor puts the tenant identity in the context, which
// the auth interceptor of the daemon does from the verified token.

// cliTenant is the tenant of the CLI session in these tests.
const cliTenant = "acme"

// serveCombinedSecrets serves the combined secrets server on a loopback port
// and returns its address and the in-memory broker behind it.
func serveCombinedSecrets(t *testing.T) (string, *fakeBroker) {
	t.Helper()
	secretsSrv, broker, _, _, _ := newTestServer(t)
	tenantSrv, _, _, _, _, _, _ := newTenantTestServer(t)

	tid, err := auth.NewTenantID(cliTenant)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	withTenant := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(auth.WithIdentity(ctx, auth.Identity{Tenant: tid, Subject: "cli-user"}), req)
	}

	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(withTenant))
	secretsv1.RegisterSecretsServiceServer(srv, NewCombinedSecretsServer(tenantSrv, secretsSrv))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	return lis.Addr().String(), broker
}

// writeCLISession writes the session file of the CLI,
// ~/.gibson/auth/credentials, under a temporary HOME. The shape is the
// documented on-disk format of the adk CLI. The token is not checked: the
// test server has no token validation, as above.
func writeCLISession(t *testing.T, addr string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	session := map[string]any{ //nolint:gosec // G101: a fake token. The test server checks no token.
		"issuer":        "http://127.0.0.1:1",
		"client_id":     "gibson-cli",
		"token_url":     "http://127.0.0.1:1/token",
		"access_token":  "cli-test-token",
		"expiry":        time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"active_tenant": cliTenant,
		"gibson_url":    "http://" + addr,
	}
	b, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal the session: %v", err)
	}
	dir := filepath.Join(home, ".gibson", "auth")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create the session dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials"), b, 0o600); err != nil {
		t.Fatalf("write the session: %v", err)
	}
}

// runSecretCLI runs `gibson secret <args...>` and returns its output.
func runSecretCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := secret.Command()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestSecretCLI_AgainstTheDaemonServer drives each value command of the CLI
// through the daemon server and checks the stored bytes after each step.
func TestSecretCLI_AgainstTheDaemonServer(t *testing.T) {
	addr, broker := serveCombinedSecrets(t)
	writeCLISession(t, addr)

	const name = "cred:goat-cluster"
	valueFile := filepath.Join(t.TempDir(), "value")
	writeValue := func(v string) {
		t.Helper()
		if err := os.WriteFile(valueFile, []byte(v), 0o600); err != nil {
			t.Fatalf("write the value file: %v", err)
		}
	}

	writeValue("first-value")
	out, err := runSecretCLI(t, "set", name, "--from-file", valueFile)
	if err != nil {
		t.Fatalf("secret set: %v\n%s", err, out)
	}
	if !strings.Contains(out, name) {
		t.Errorf("secret set printed %q, want the name %q", out, name)
	}
	if got := string(broker.store[name]); got != "first-value" {
		t.Fatalf("after set, the broker holds %q, want %q", got, "first-value")
	}

	out, err = runSecretCLI(t, "get", name)
	if err != nil {
		t.Fatalf("secret get: %v\n%s", err, out)
	}
	if !strings.Contains(out, name) || !strings.Contains(out, "SECRET_CATEGORY_CRED") {
		t.Errorf("secret get printed %q, want the name and the category", out)
	}
	if strings.Contains(out, "first-value") {
		t.Errorf("secret get printed the value: %q", out)
	}

	out, err = runSecretCLI(t, "list", "--prefix", "cred:")
	if err != nil {
		t.Fatalf("secret list: %v\n%s", err, out)
	}
	if !strings.Contains(out, name) {
		t.Errorf("secret list printed %q, want the name %q", out, name)
	}

	writeValue("second-value")
	out, err = runSecretCLI(t, "rotate", name, "--from-file", valueFile)
	if err != nil {
		t.Fatalf("secret rotate: %v\n%s", err, out)
	}
	if got := string(broker.store[name]); got != "second-value" {
		t.Fatalf("after rotate, the broker holds %q, want %q", got, "second-value")
	}

	out, err = runSecretCLI(t, "delete", name, "--yes")
	if err != nil {
		t.Fatalf("secret delete: %v\n%s", err, out)
	}
	if _, ok := broker.store[name]; ok {
		t.Fatalf("after delete, the broker still holds %q", name)
	}

	if out, err = runSecretCLI(t, "get", name); err == nil {
		t.Fatalf("secret get after delete succeeded: %q", out)
	}
}
