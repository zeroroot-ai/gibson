// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// probeMount writes an RSA key and, when user is not empty, the user file.
func probeMount(t *testing.T, user string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "private-key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if user != "" {
		if err := os.WriteFile(filepath.Join(dir, zitadel.SystemUserFile), []byte(user), 0o600); err != nil {
			t.Fatalf("write user: %v", err)
		}
	}
	return path
}

func TestSystemKeyProbe_KeyAndUser(t *testing.T) {
	p := &systemKeyProbe{path: probeMount(t, "gibson-system-bot")}
	if err := p.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestSystemKeyProbe_NoUserFails(t *testing.T) {
	p := &systemKeyProbe{path: probeMount(t, "")}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("Check with no user file: want an error, got nil")
	}
}

func TestSystemKeyProbe_NoKeyFails(t *testing.T) {
	p := &systemKeyProbe{path: filepath.Join(t.TempDir(), "absent.pem")}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("Check with no key: want an error, got nil")
	}
}
