/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import (
	"strings"
	"testing"
)

// TestValidateFGAEnvKeys is the operator startup contract from
// one-code-path slice deploy#195: missing FGA env vars must produce a
// non-nil error naming the missing key(s).
func TestValidateFGAEnvKeys(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		wantErr     bool
		wantNamings []string // substrings the error must mention
	}{
		{
			name: "both set → ok",
			env: map[string]string{
				"FGA_URL":      "http://gibson-openfga:8080",
				"FGA_STORE_ID": "01H...",
			},
			wantErr: false,
		},
		{
			name: "url missing → error names FGA_URL",
			env: map[string]string{
				"FGA_STORE_ID": "01H...",
			},
			wantErr:     true,
			wantNamings: []string{"FGA_URL"},
		},
		{
			name: "store_id missing → error names FGA_STORE_ID",
			env: map[string]string{
				"FGA_URL": "http://gibson-openfga:8080",
			},
			wantErr:     true,
			wantNamings: []string{"FGA_STORE_ID"},
		},
		{
			name:        "both missing → error names both",
			env:         map[string]string{},
			wantErr:     true,
			wantNamings: []string{"FGA_URL", "FGA_STORE_ID"},
		},
		{
			name: "empty string values count as missing",
			env: map[string]string{
				"FGA_URL":      "",
				"FGA_STORE_ID": "",
			},
			wantErr:     true,
			wantNamings: []string{"FGA_URL", "FGA_STORE_ID"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			err := validateFGAEnvKeys(getenv)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				for _, sub := range tc.wantNamings {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("expected error to mention %q, got: %v", sub, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got: %v", err)
			}
		})
	}
}
