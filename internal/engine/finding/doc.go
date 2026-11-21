// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package finding holds the daemon's finding types. The finding store is in
// the pgstore sub-package. It keeps each finding in the Postgres database of
// the tenant.
//
// # Types
//
// EnhancedFinding embeds agent.Finding and adds a category, a status and
// MITRE mappings (types.go). The evidence of a finding is types.v1.Evidence,
// the one evidence shape. EvidenceTypeName and EvidenceTypeFromName map its
// type enum to the names that the SDK and the predicates of a Domain Pack use
// (evidence.go). MitreMapping and MitreTechnique carry an ATT&CK
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
// The export of findings is in internal/server/daemon/api/export_findings.go. It
// reads the findings and their evidence from pgstore.
package finding
