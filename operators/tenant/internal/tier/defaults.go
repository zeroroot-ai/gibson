/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package tier loads tier-based default component grants from a YAML
// ConfigMap mounted at a known path. Supports hot-reload via fsnotify.
package tier

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// yamlDefaults is the on-disk schema.
type yamlDefaults struct {
	Tiers map[string]struct {
		Tools   []string `yaml:"tools"`
		Agents  []string `yaml:"agents"`
		Plugins []string `yaml:"plugins"`
	} `yaml:"tiers"`
}

// Defaults loads and serves tier defaults.
type Defaults struct {
	path string
	mu   sync.RWMutex
	data yamlDefaults
}

// NewDefaults loads defaults from the given YAML file path. Missing file
// is not an error — empty defaults are returned until a file appears.
func NewDefaults(path string) (*Defaults, error) {
	d := &Defaults{path: path}
	if err := d.Reload(); err != nil {
		// Tolerate missing file at startup; reload on first change.
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return d, nil
}

// Reload re-reads the file from disk.
func (d *Defaults) Reload() error {
	raw, err := os.ReadFile(d.path)
	if err != nil {
		return err
	}
	var parsed yamlDefaults
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("parse tier defaults: %w", err)
	}
	d.mu.Lock()
	d.data = parsed
	d.mu.Unlock()
	return nil
}

// GrantsForTier returns the component refs granted by default for the tier.
// Expands wildcard "*" requires the caller to pass knownComponents per kind.
func (d *Defaults) GrantsForTier(tier gibsonv1alpha1.TenantTier, knownTools, knownAgents, knownPlugins []string) []gibsonv1alpha1.ComponentRef {
	d.mu.RLock()
	defer d.mu.RUnlock()
	t, ok := d.data.Tiers[string(tier)]
	if !ok {
		return nil
	}
	out := make([]gibsonv1alpha1.ComponentRef, 0, len(t.Tools)+len(t.Agents)+len(t.Plugins))
	out = append(out, expandRefs(gibsonv1alpha1.ComponentKindTool, t.Tools, knownTools)...)
	out = append(out, expandRefs(gibsonv1alpha1.ComponentKindAgent, t.Agents, knownAgents)...)
	out = append(out, expandRefs(gibsonv1alpha1.ComponentKindPlugin, t.Plugins, knownPlugins)...)
	return out
}

func expandRefs(kind gibsonv1alpha1.ComponentKind, names, known []string) []gibsonv1alpha1.ComponentRef {
	var out []gibsonv1alpha1.ComponentRef
	for _, n := range names {
		if n == "*" {
			for _, k := range known {
				out = append(out, gibsonv1alpha1.ComponentRef{Kind: kind, Name: k})
			}
			continue
		}
		out = append(out, gibsonv1alpha1.ComponentRef{Kind: kind, Name: n})
	}
	return out
}
