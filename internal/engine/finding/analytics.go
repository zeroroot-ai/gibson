// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

// TechniqueCount represents a MITRE technique with its occurrence count
type TechniqueCount struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Count         int    `json:"count"`
}
