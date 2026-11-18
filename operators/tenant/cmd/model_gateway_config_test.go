// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"
)

func TestModelGatewayConfigFromEnv(t *testing.T) {
	full := map[string]string{
		envModelGatewayNamespace:       "gibson-gateway",
		envModelGatewayName:            "model-gateway",
		envModelGatewayExtAuthzService: "gibson-ext-authz",
		envModelGatewayExtAuthzPort:    "9001",
	}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	cfg, err := modelGatewayConfigFromEnv(get(full))
	if err != nil || cfg.Namespace != "gibson-gateway" || cfg.ExtAuthzPort != 9001 || cfg.ExtAuthzNamespace != "" {
		t.Fatalf("config = %+v, %v", cfg, err)
	}

	for name := range full {
		partial := map[string]string{}
		for k, v := range full {
			if k != name {
				partial[k] = v
			}
		}
		if _, err := modelGatewayConfigFromEnv(get(partial)); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: error = %v, want it to name the variable", name, err)
		}
	}
	for _, bad := range []string{"abc", "0", "70000"} {
		full[envModelGatewayExtAuthzPort] = bad
		if _, err := modelGatewayConfigFromEnv(get(full)); err == nil {
			t.Errorf("port %q gave no error", bad)
		}
	}
}
