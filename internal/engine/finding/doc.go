// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finding holds the daemon's finding types and the store that keeps
// findings in the tenant's Redis.
//
// # Types
//
// EnhancedFinding embeds agent.Finding and adds a category, a status, MITRE
// mappings and structured evidence (types.go). EnhancedEvidence is one item of
// evidence: an HTTP request, an HTTP response, a conversation, or free text
// (evidence.go). MitreMapping and MitreTechnique carry an ATT&CK or ATLAS
// technique (mitre.go).
//
// # Store
//
// FindingStore is the write interface. ConnBoundFindingStore implements it on
// one Redis connection, and that connection is the tenant boundary: the store
// reads and writes only the database the connection selects
// (store_conn.go). FindingFilter narrows a List call.
//
// # Compliance updates
//
// compliance_update.go defines the interfaces a compliance flow uses to change
// a stored finding and to write the audit record of the change.
//
// # Export
//
// The export sub-package renders findings as JSON, SARIF 2.1.0, CSV, HTML and
// Markdown.
package finding
