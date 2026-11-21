// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// connectorInstallPatternsEnv holds the host patterns that the platform owner
// of the install states for the connectors of a server that the customer
// hosts, as JSON: {"<connector>/<variable>": ["https://git.example.com"]}.
// The chart sets it. The tenant never does (review B3).
const connectorInstallPatternsEnv = "GIBSON_CONNECTOR_INSTALL_PATTERNS"

// loadConnectorInstallPatterns reads the install patterns and sets them on
// the catalog. An empty value sets none. A value that does not parse, or a
// pattern that the catalog refuses, is an error.
func loadConnectorInstallPatterns(getenv func(string) string) error {
	raw := strings.TrimSpace(getenv(connectorInstallPatternsEnv))
	var m map[string][]string
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return fmt.Errorf("%s: %w", connectorInstallPatternsEnv, err)
		}
	}
	if err := componentcatalog.SetInstallPatterns(m); err != nil {
		return fmt.Errorf("%s: %w", connectorInstallPatternsEnv, err)
	}
	return nil
}
