// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeMount writes a key file and, when user is not nil, the user file
// beside it. It returns the key path.
func writeMount(t *testing.T, user *string) string {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "private-key.pem")
	if err := os.WriteFile(key, []byte("not read by ReadSystemUser"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if user != nil {
		if err := os.WriteFile(filepath.Join(dir, SystemUserFile), []byte(*user), 0o600); err != nil {
			t.Fatalf("write user: %v", err)
		}
	}
	return key
}

func strp(s string) *string { return &s }

func TestReadSystemUser_FromTheMount(t *testing.T) {
	got, err := ReadSystemUser(writeMount(t, strp("gibson-system-bot-b\n")))
	if err != nil {
		t.Fatalf("ReadSystemUser: %v", err)
	}
	if got != "gibson-system-bot-b" {
		t.Errorf("user = %q, want gibson-system-bot-b", got)
	}
}

func TestReadSystemUser_NoUserFileIsAnError(t *testing.T) {
	if _, err := ReadSystemUser(writeMount(t, nil)); err == nil {
		t.Fatal("ReadSystemUser with no user file: want an error, got nil")
	}
}

func TestReadSystemUser_EmptyUserIsAnError(t *testing.T) {
	_, err := ReadSystemUser(writeMount(t, strp(" \n")))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ReadSystemUser with an empty user: err = %v, want ErrInvalidInput", err)
	}
}

func TestResolveSystemKeyPath(t *testing.T) {
	t.Setenv("ZITADEL_SYSTEM_KEY_PATH", "")
	if got := ResolveSystemKeyPath(""); got != DefaultSystemKeyPath {
		t.Errorf("no path and no env: %q, want %q", got, DefaultSystemKeyPath)
	}
	t.Setenv("ZITADEL_SYSTEM_KEY_PATH", "/env/key.pem")
	if got := ResolveSystemKeyPath(""); got != "/env/key.pem" {
		t.Errorf("env: %q, want /env/key.pem", got)
	}
	if got := ResolveSystemKeyPath("/spec/key.pem"); got != "/spec/key.pem" {
		t.Errorf("spec path: %q, want /spec/key.pem", got)
	}
}

// The env path reaches the user file next to it.
func TestReadSystemUser_FollowsTheEnvPath(t *testing.T) {
	t.Setenv("ZITADEL_SYSTEM_KEY_PATH", writeMount(t, strp("gibson-system-bot")))
	got, err := ReadSystemUser("")
	if err != nil || got != "gibson-system-bot" {
		t.Fatalf("ReadSystemUser(\"\") = %q, %v; want gibson-system-bot", got, err)
	}
}
