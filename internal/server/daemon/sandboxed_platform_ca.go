// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// platformCAPEM reads the platform edge CA the sandbox launcher hands to
// every agent and member launch (gibson#13). A missing file is the public
// roots case and yields nothing. A file that is present but holds no
// CERTIFICATE block is a misconfiguration, reported and treated as absent:
// the launch still happens, and the member says what it could not verify.
func platformCAPEM(path string, logger *slog.Logger) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the daemon's own config, a mounted CA file
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Warn("platform CA file is unreadable; sandboxes get no platform CA", "path", path, "error", err)
		}
		return ""
	}
	if err := checkCertificatePEM(raw); err != nil {
		logger.Warn("platform CA file carries no certificate; sandboxes get no platform CA", "path", path, "error", err)
		return ""
	}
	return string(raw)
}

// checkCertificatePEM reports whether data holds at least one PEM
// CERTIFICATE block and nothing of another type.
func checkCertificatePEM(data []byte) error {
	var blocks int
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("PEM block %q is not a CERTIFICATE", block.Type)
		}
		blocks++
		data = rest
	}
	if blocks == 0 {
		return errors.New("no PEM CERTIFICATE block")
	}
	return nil
}
