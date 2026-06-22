/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// system_tenant_kek.go — load the system-tenant KEK from either a file
// (preferred — works for both base64-text and raw-bytes Secret values)
// or an env var (legacy path, kept for backward compat with overlays
// whose Secret values are pre-base64-encoded text).
//
// deploy#173: the daemon's k8s key_provider reads the same Secret via
// the Kubernetes API at runtime. The operator now does the equivalent
// via a Helm-mounted Secret volume. env-var injection of raw 32 bytes
// crashes the pod with "value contains nul byte" — file mount sidesteps
// the issue entirely.

package main

import (
	"encoding/base64"
	"os"

	"github.com/go-logr/logr"
)

// loadSystemTenantKEK returns the 32-byte system-tenant KEK. Returns
// (nil, nil) on graceful no-op (env unset AND path unset AND no file
// found — operator logs and continues; the WriteTenantBrokerConfig saga
// step skips). Returns (nil, err) on hard errors (file exists but is
// not 32 bytes, env is set but not parseable, etc.) and the caller
// should log + degrade.
//
// Resolution order:
//  1. GIBSON_SYSTEM_TENANT_KEK_PATH — read raw bytes from the file. If
//     the file is exactly 32 bytes, that's the KEK as-is. If it's 44
//     bytes of valid base64, decode it. Anything else is an error.
//  2. GIBSON_SYSTEM_TENANT_KEK — base64-decode the env value.
//  3. Neither set — graceful no-op.
func loadSystemTenantKEK(log logr.Logger) []byte {
	if path := os.Getenv("GIBSON_SYSTEM_TENANT_KEK_PATH"); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path comes from operator chart, not user input
		if err != nil {
			log.Error(err, "GIBSON_SYSTEM_TENANT_KEK_PATH read failed — WriteTenantBrokerConfig step disabled",
				"path", path)
			return nil
		}
		// Files written via Kubernetes Secret volumes don't carry trailing
		// newlines, but ConfigMaps occasionally do — trim defensively.
		data = trimTrailingNewline(data)
		switch len(data) {
		case 32:
			return data
		case 44:
			// 32 raw bytes base64-encoded with one '=' pad is 44 chars.
			kek, err := base64.StdEncoding.DecodeString(string(data))
			if err != nil {
				log.Error(err, "GIBSON_SYSTEM_TENANT_KEK_PATH content is 44 bytes but not valid base64",
					"path", path)
				return nil
			}
			if len(kek) != 32 {
				log.Info("GIBSON_SYSTEM_TENANT_KEK_PATH base64-decoded to wrong length",
					"path", path, "got", len(kek))
				return nil
			}
			return kek
		default:
			log.Info("GIBSON_SYSTEM_TENANT_KEK_PATH must be 32 raw bytes or 44 base64 chars",
				"path", path, "got_bytes", len(data))
			return nil
		}
	}

	kekB64 := os.Getenv("GIBSON_SYSTEM_TENANT_KEK")
	if kekB64 == "" {
		log.Info("GIBSON_SYSTEM_TENANT_KEK / _PATH both unset — WriteTenantBrokerConfig step will no-op")
		return nil
	}
	kek, err := base64.StdEncoding.DecodeString(kekB64)
	if err != nil {
		log.Error(err, "GIBSON_SYSTEM_TENANT_KEK is not valid base64 — WriteTenantBrokerConfig step disabled")
		return nil
	}
	if len(kek) != 32 {
		log.Info("GIBSON_SYSTEM_TENANT_KEK must decode to 32 bytes — WriteTenantBrokerConfig step disabled",
			"got", len(kek))
		return nil
	}
	return kek
}

// trimTrailingNewline strips a single \n (and optional preceding \r) so a
// ConfigMap-written value with a trailing newline still parses.
func trimTrailingNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}
