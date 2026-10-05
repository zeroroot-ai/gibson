// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package auditcel

import (
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// ErrNilDomainPack is returned by LoadMappingRules for a nil pack.
var ErrNilDomainPack = errors.New("auditcel: domain pack must not be nil")

// LoadMappingRules compiles each mapping rule of pack against one audit
// event environment and returns the rules keyed by control id. It fails
// closed: pack.Validate runs first, and the first rule that does not
// compile fails the whole load. A pack with one bad rule loads none.
func LoadMappingRules(pack *ontology.DomainPack) (map[string]*CompiledRule, error) {
	if pack == nil {
		return nil, ErrNilDomainPack
	}
	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("auditcel: load domain pack %q: %w", pack.Name, err)
	}
	compiled := make(map[string]*CompiledRule, len(pack.MappingRules))
	if len(pack.MappingRules) == 0 {
		return compiled, nil
	}
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("auditcel: load domain pack %q: %w", pack.Name, err)
	}
	// The rules are a slice, so the first bad rule is the same on each run.
	for _, rule := range pack.MappingRules {
		cr, err := CompileWithEnv(env, rule.Expression)
		if err != nil {
			return nil, fmt.Errorf("auditcel: load domain pack %q: control %q: %w", pack.Name, rule.ControlID, err)
		}
		compiled[rule.ControlID] = cr
	}
	return compiled, nil
}
