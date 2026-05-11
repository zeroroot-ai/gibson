package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout replaces os.Stdout for the duration of f and returns whatever
// was written. Errors during capture are fatal.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	return buf.String()
}

// ---------------------------------------------------------------------------
// Subcommand routing
// ---------------------------------------------------------------------------

func TestRun_NoArgs(t *testing.T) {
	err := run(context.Background(), nil)
	if err == nil {
		t.Fatal("want error for no args, got nil")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Errorf("error should mention usage, got: %v", err)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	err := run(context.Background(), []string{"notacommand"})
	if err == nil {
		t.Fatal("want error for unknown subcommand, got nil")
	}
	if !strings.Contains(err.Error(), "unknown subcommand") {
		t.Errorf("error should mention unknown subcommand, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Table-driven subcommand routing
// ---------------------------------------------------------------------------

func TestRun_Routing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{},
			wantErr: "usage",
		},
		{
			name:    "empty first arg",
			args:    []string{""},
			wantErr: "unknown subcommand",
		},
		{
			name:    "unknown subcommand",
			args:    []string{"zitadel-do-something-weird"},
			wantErr: "unknown subcommand",
		},
		{
			name:    "ensure-org missing env",
			args:    []string{"zitadel-ensure-org", "my-org"},
			wantErr: "ZITADEL_ISSUER", // env not set in test
		},
		{
			name:    "ensure-org missing name arg",
			args:    []string{"zitadel-ensure-org"},
			wantErr: "usage",
		},
		{
			name:    "mint-oidc-client missing env",
			args:    []string{"zitadel-mint-oidc-client", "my-client"},
			wantErr: "ZITADEL_ISSUER",
		},
		{
			name:    "mint-oidc-client missing name arg",
			args:    []string{"zitadel-mint-oidc-client"},
			wantErr: "usage",
		},
		{
			name:    "mint-oidc-client unknown flag",
			args:    []string{"zitadel-mint-oidc-client", "my-client", "--unknown-flag"},
			wantErr: "unknown flag", // flag parsing happens before env validation
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure env is clean for these tests.
			t.Setenv("ZITADEL_ISSUER", "")
			t.Setenv("ZITADEL_ADMIN_PAT", "")
			t.Setenv("ZITADEL_ORG_ID", "")
			t.Setenv("ZITADEL_PROJECT_ID", "")

			err := run(context.Background(), tc.args)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// writeJSON contract
// ---------------------------------------------------------------------------

func TestWriteJSON_SingleLine(t *testing.T) {
	type payload struct {
		OrgID   string `json:"org_id"`
		Created bool   `json:"created"`
	}

	out := captureStdout(t, func() {
		if err := writeJSON(payload{OrgID: "org-abc", Created: true}); err != nil {
			t.Errorf("writeJSON: %v", err)
		}
	})

	// Must be exactly one line (trailing newline is allowed; no embedded newlines).
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("writeJSON output must be exactly one line, got %d: %q", len(lines), out)
	}

	// Must be valid JSON.
	if !strings.HasPrefix(lines[0], "{") {
		t.Errorf("output must be a JSON object, got: %q", lines[0])
	}
}

func TestWriteJSON_NoMultilineOutput(t *testing.T) {
	type payload struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Rotated      bool   `json:"rotated"`
	}

	out := captureStdout(t, func() {
		if err := writeJSON(payload{
			ClientID:     "client-123",
			ClientSecret: "s3cr3t",
			Rotated:      false,
		}); err != nil {
			t.Errorf("writeJSON: %v", err)
		}
	})

	trimmed := strings.TrimRight(out, "\n")
	if strings.Contains(trimmed, "\n") {
		t.Errorf("writeJSON must not emit multi-line output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// mintOIDCClient flag parsing
// ---------------------------------------------------------------------------

func TestCmdMintOIDCClient_UnknownFlag(t *testing.T) {
	// With env set but an unknown flag, we expect an "unknown flag" error.
	t.Setenv("ZITADEL_ISSUER", "http://zitadel.test")
	t.Setenv("ZITADEL_ADMIN_PAT", "testpat")
	t.Setenv("ZITADEL_ORG_ID", "org-1")
	t.Setenv("ZITADEL_PROJECT_ID", "proj-1")

	err := run(context.Background(), []string{"zitadel-mint-oidc-client", "my-client", "--bad-flag"})
	if err == nil {
		t.Fatal("want error for unknown flag, got nil")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("want 'unknown flag' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// patClientConfig env validation
// ---------------------------------------------------------------------------

func TestPatClientConfig_MissingIssuer(t *testing.T) {
	t.Setenv("ZITADEL_ISSUER", "")
	t.Setenv("ZITADEL_ADMIN_PAT", "token")

	_, err := loadPATClientConfig()
	if err == nil {
		t.Fatal("want error when ZITADEL_ISSUER is missing, got nil")
	}
	if !strings.Contains(err.Error(), "ZITADEL_ISSUER") {
		t.Errorf("error should mention ZITADEL_ISSUER, got: %v", err)
	}
}

func TestPatClientConfig_MissingPAT(t *testing.T) {
	t.Setenv("ZITADEL_ISSUER", "http://zitadel.test")
	t.Setenv("ZITADEL_ADMIN_PAT", "")

	_, err := loadPATClientConfig()
	if err == nil {
		t.Fatal("want error when ZITADEL_ADMIN_PAT is missing, got nil")
	}
	if !strings.Contains(err.Error(), "ZITADEL_ADMIN_PAT") {
		t.Errorf("error should mention ZITADEL_ADMIN_PAT, got: %v", err)
	}
}

func TestPatClientConfig_TrailingSlashStripped(t *testing.T) {
	t.Setenv("ZITADEL_ISSUER", "http://zitadel.test/")
	t.Setenv("ZITADEL_ADMIN_PAT", "tok")

	cfg, err := loadPATClientConfig()
	if err != nil {
		t.Fatalf("loadPATClientConfig: %v", err)
	}
	if strings.HasSuffix(cfg.Issuer, "/") {
		t.Errorf("Issuer should have trailing slash stripped, got: %q", cfg.Issuer)
	}
}

// ---------------------------------------------------------------------------
// bootstrapAPIError
// ---------------------------------------------------------------------------

func TestBootstrapAPIError_Format(t *testing.T) {
	err := &bootstrapAPIError{status: 409, code: "ALREADY_EXISTS", message: "already exists"}
	got := err.Error()
	if !strings.Contains(got, "409") {
		t.Errorf("error should contain status code 409, got: %q", got)
	}
	if !strings.Contains(got, "ALREADY_EXISTS") {
		t.Errorf("error should contain error code, got: %q", got)
	}
}

func TestIsConflict_True(t *testing.T) {
	err := &bootstrapAPIError{status: 409}
	if !isConflict(err) {
		t.Error("isConflict should be true for 409")
	}
}

func TestIsConflict_False(t *testing.T) {
	tests := []error{
		nil,
		&bootstrapAPIError{status: 404},
		&bootstrapAPIError{status: 500},
		fmt.Errorf("generic error"),
	}
	for _, err := range tests {
		if isConflict(err) {
			t.Errorf("isConflict should be false for %v", err)
		}
	}
}
