// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countermeasurePack returns a small valid pack with countermeasures.
func countermeasurePack() DomainPack {
	return DomainPack{
		Name:                      "cm",
		Version:                   1,
		TaxonomyNodeLabels:        []string{CountermeasureLabel},
		TaxonomyRelationshipTypes: []string{CountersRelationshipType},
		TaxonomyNodeIdentity:      map[string]string{CountermeasureLabel: CountermeasureIdentityProperty},
		CountermeasureTactics:     []string{"Detect", "Harden"},
		Countermeasures: []Countermeasure{
			{ID: "D3-FA", Name: "File Analysis", Tactic: "Detect", Counters: []string{"T1059", "T1059.001"},
				NISTControls: []string{"si-3.10"}},
			{ID: "D3-DA", Name: "Dynamic Analysis", Tactic: "Detect", Parent: "D3-FA", Counters: []string{"T1059.001"}},
			{ID: "D3-AH", Name: "Application Hardening", Tactic: "Harden"},
		},
	}
}

func TestCountermeasurePack_IsValid(t *testing.T) {
	p := countermeasurePack()
	require.NoError(t, p.Validate())
}

func TestCountermeasuresFor(t *testing.T) {
	p := countermeasurePack()
	got := p.CountermeasuresFor("T1059.001")
	require.Len(t, got, 2)
	assert.Equal(t, "D3-FA", got[0].ID)
	assert.Equal(t, "D3-DA", got[1].ID)
	assert.Len(t, p.CountermeasuresFor("T1059"), 1)
	assert.Empty(t, p.CountermeasuresFor("T9999"))
	assert.Empty(t, p.CountermeasuresFor("not a technique"))
	assert.Empty(t, p.CountermeasuresFor(""))
}

func TestCountermeasuresForControl(t *testing.T) {
	p := countermeasurePack()
	got := p.CountermeasuresForControl("si-3.10")
	require.Len(t, got, 1)
	assert.Equal(t, "D3-FA", got[0].ID)
	assert.Empty(t, p.CountermeasuresForControl("ac-2"))
}

func TestCountermeasure_Refusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(p *DomainPack)
		want   string
	}{
		"bad id":          {func(p *DomainPack) { p.Countermeasures[0].ID = "FA" }, "D3-XXX"},
		"duplicate id":    {func(p *DomainPack) { p.Countermeasures[1].ID = "D3-FA" }, "listed twice"},
		"empty name":      {func(p *DomainPack) { p.Countermeasures[0].Name = " " }, "name"},
		"unknown tactic":  {func(p *DomainPack) { p.Countermeasures[0].Tactic = "Evict" }, "not a tactic"},
		"unknown parent":  {func(p *DomainPack) { p.Countermeasures[1].Parent = "D3-ZZ" }, "parent"},
		"parent cycle":    {func(p *DomainPack) { p.Countermeasures[0].Parent = "D3-DA" }, "cycle"},
		"bad technique":   {func(p *DomainPack) { p.Countermeasures[0].Counters = []string{"1059"} }, "ATT&CK"},
		"twice technique": {func(p *DomainPack) { p.Countermeasures[0].Counters = []string{"T1059", "T1059"} }, "twice"},
		"bad control":     {func(p *DomainPack) { p.Countermeasures[0].NISTControls = []string{"ac 2"} }, "control id"},
		"no label":        {func(p *DomainPack) { p.TaxonomyNodeLabels = nil; p.TaxonomyNodeIdentity = nil }, "must promote"},
		"no relation":     {func(p *DomainPack) { p.TaxonomyRelationshipTypes = nil }, "must promote"},
		"no tactics":      {func(p *DomainPack) { p.CountermeasureTactics = nil }, "tactics"},
		"tactics alone": {func(p *DomainPack) {
			p.Countermeasures = nil
		}, "no countermeasure"},
		"too many": {func(p *DomainPack) {
			p.Countermeasures = make([]Countermeasure, MaxCountermeasures+1)
		}, "cap"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := countermeasurePack()
			tc.mutate(&p)
			err := p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestPackSource_Refusals(t *testing.T) {
	p := countermeasurePack()
	p.Source = &PackSource{Name: "n", Release: "1", URL: "u", License: "MIT", SHA256: ""}
	require.Error(t, p.Validate())
	p.Source.SHA256 = "abc"
	require.NoError(t, p.Validate())
}
