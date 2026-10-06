// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

// MitreMapping represents a mapping to a MITRE technique
type MitreMapping struct {
	Matrix        string   `json:"matrix"`                   // "ATT&CK" or "ATLAS"
	TacticID      string   `json:"tactic_id"`                // e.g., "TA0001"
	TacticName    string   `json:"tactic_name"`              // e.g., "Initial Access"
	TechniqueID   string   `json:"technique_id"`             // e.g., "T1566" or "AML.T0015"
	TechniqueName string   `json:"technique_name"`           // e.g., "Phishing"
	SubTechniques []string `json:"sub_techniques,omitempty"` // e.g., ["T1566.001", "T1566.002"]
}

// MitreTechnique represents a MITRE technique with full details
type MitreTechnique struct {
	ID          string   `json:"id"`   // e.g., "AML.T0015"
	Name        string   `json:"name"` // e.g., "Jailbreak"
	Description string   `json:"description"`
	TacticIDs   []string `json:"tactic_ids"` // Associated tactic IDs
	URL         string   `json:"url"`        // Reference URL
}
