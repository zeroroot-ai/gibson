// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finding holds the daemon's finding types. The finding store is in
// the pgstore sub-package. It keeps each finding in the Postgres database of
// the tenant.
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
// FindingStore is the write interface. pgstore.Store implements it. It keeps
// one row for each finding in the findings table of the database of the tenant.
// That database is the tenant boundary. FindingFilter narrows a List call.
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
