// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The config comes from the environment of the operator, one variable for
// each fact, and each missing value is refused by name.
func TestCatalogPluginConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"PLUGIN_SPIRE_CLASS_NAME":     "gibson-plugins",
		"PLUGIN_TRUST_DOMAIN":         "example.org",
		"PLUGIN_GIBSON_URL":           "https://gibson.example",
		"PLUGIN_ENVOY_CA_FILE":        "/etc/ca.pem",
		"PLUGIN_WAIT_FOR_SPIRE_IMAGE": "ghcr.io/x/wait@sha256:aa",
		envOperatorSAName:             "tenant-operator",
		envOperatorSANamespace:        "gibson",
	}
	cfg := CatalogPluginConfigFromEnv(func(k string) string { return env[k] })
	if cfg.SpireClassName != "gibson-plugins" || cfg.TrustDomain != "example.org" || cfg.GibsonURL != "https://gibson.example" ||
		cfg.EnvoyCAFile != "/etc/ca.pem" || cfg.WaitForSpireImage != "ghcr.io/x/wait@sha256:aa" ||
		cfg.OperatorServiceAccount != "tenant-operator" || cfg.OperatorNamespace != "gibson" {
		t.Fatalf("config = %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a full config: %v", err)
	}
	for _, name := range []string{"PLUGIN_SPIRE_CLASS_NAME", "PLUGIN_TRUST_DOMAIN", "PLUGIN_GIBSON_URL", "PLUGIN_WAIT_FOR_SPIRE_IMAGE", envOperatorSAName, envOperatorSANamespace} {
		partial := map[string]string{}
		for k, v := range env {
			partial[k] = v
		}
		delete(partial, name)
		err := CatalogPluginConfigFromEnv(func(k string) string { return partial[k] }).Validate()
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: err = %v, want the name", name, err)
		}
	}
}

// The loop refuses to start with no daemon client or a bad config.
func TestCatalogPluginRunnable_SetupRefusesABadInput(t *testing.T) {
	r := &CatalogPluginRunnable{Config: cpConfig()}
	if err := r.SetupWithManager(nil); err == nil || !strings.Contains(err.Error(), "Daemon client is nil") {
		t.Fatalf("no daemon: %v", err)
	}
	r = &CatalogPluginRunnable{Daemon: &fakeCatalogPluginDaemon{}}
	if err := r.SetupWithManager(nil); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("a bad config: %v", err)
	}
}

// Start converges at each interval and stops with the context.
func TestCatalogPluginRunnable_StartStopsWithTheContext(t *testing.T) {
	d := &fakeCatalogPluginDaemon{}
	r, _ := newCatalogPluginLoop(t, d, cpTenantObject("acme"))
	r.Interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not stop after the context ended")
	}
}
