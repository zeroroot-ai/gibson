// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"strings"
	"testing"
)

// The operator does not start without each value of the trainer config, and
// the error names the variables to set.
func TestBeliefTrainerConfigFromEnv(t *testing.T) {
	env := map[string]string{
		envBeliefTrainerImage: "ghcr.io/zeroroot-ai/gibson:v1",
		envDaemonGRPCAddress:  "gibson.gibson.svc:50051",
		envDaemonSPIFFEID:     "spiffe://example.org/platform/daemon",
		"OPERATOR_NAMESPACE":  "gibson",
	}
	cfg, err := beliefTrainerConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("beliefTrainerConfigFromEnv: %v", err)
	}
	if cfg.Image != env[envBeliefTrainerImage] || cfg.PlatformNamespace != "gibson" {
		t.Errorf("config = %+v", cfg)
	}

	delete(env, envBeliefTrainerImage)
	_, err = beliefTrainerConfigFromEnv(func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), envBeliefTrainerImage) {
		t.Fatalf("no image: err = %v, want an error that names %s", err, envBeliefTrainerImage)
	}
}
