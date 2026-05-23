// Package catalogue provides a static provider-catalogue.yaml embedded in the
// binary. The catalogue is the source of truth for which models each provider
// exposes; it is populated once at startup via Load() and thereafter read-only.
package catalogue

import (
	_ "embed"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed provider-catalogue.yaml
var catalogueData []byte

// Model describes a single model entry in the catalogue.
type Model struct {
	ID            string   `yaml:"id"`
	ContextWindow int      `yaml:"context_window"`
	Capabilities  []string `yaml:"capabilities"`
	Deprecated    bool     `yaml:"deprecated"`
}

// ProviderEntry describes a provider and its static model list.
type ProviderEntry struct {
	Type           string  `yaml:"type"`
	DisplayName    string  `yaml:"display_name"`
	UpdateStrategy string  `yaml:"update_strategy"`
	Models         []Model `yaml:"models"`
}

// Catalogue is the top-level structure of provider-catalogue.yaml.
type Catalogue struct {
	Providers []ProviderEntry `yaml:"providers"`
}

var (
	once     sync.Once
	instance *Catalogue
)

// Load parses provider-catalogue.yaml exactly once and returns the singleton.
// It panics if the embedded YAML is malformed — a startup failure is the
// correct behaviour for a binary that ships a corrupt catalogue.
func Load() *Catalogue {
	once.Do(func() {
		var c Catalogue
		if err := yaml.Unmarshal(catalogueData, &c); err != nil {
			panic("provider-catalogue.yaml parse error: " + err.Error())
		}
		instance = &c
	})
	return instance
}

// ModelsFor returns the model list for the given provider type string, or nil
// if the provider is not present in the catalogue.
func ModelsFor(providerType string) []Model {
	for _, p := range Load().Providers {
		if p.Type == providerType {
			return p.Models
		}
	}
	return nil
}
