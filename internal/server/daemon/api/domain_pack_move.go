// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/auditcel"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement/celenv"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// PackImportStore stores an imported Domain Pack. *ontology.ImportStore
// implements it.
type PackImportStore interface {
	Save(ctx context.Context, pack *ontology.DomainPack, importedBy string) error
}

// ExportDomainPack returns the live extensions of the tenant of the caller
// as the JSON of one Domain Pack (gibson#712).
func (s *DomainPackService) ExportDomainPack(
	ctx context.Context, req *tenantv1.ExportDomainPackRequest,
) (*tenantv1.ExportDomainPackResponse, error) {
	e, tenantID, err := s.engine(ctx, "ExportDomainPack")
	if err != nil {
		return nil, err
	}
	var nodeLabels, relTypes []string
	for _, p := range e.OntologyProposals() {
		if !p.Promoted {
			continue
		}
		switch p.ProposalKind {
		case taxonomy.ProposedNodeLabel:
			nodeLabels = append(nodeLabels, p.Label)
		case taxonomy.ProposedRelationshipType:
			relTypes = append(relTypes, p.Label)
		}
	}
	pack, err := ontology.ExportTenantExtensions(req.GetName(), int(req.GetVersion()), tenantID.String(), nodeLabels, relTypes)
	if err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ExportDomainPack: %v", err)
	}
	raw, err := ontology.EncodePackJSON(pack)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "ExportDomainPack: %v", err)
	}
	return &tenantv1.ExportDomainPackResponse{PackJson: raw}, nil
}

// ImportDomainPack checks the JSON of one Domain Pack and stores it in this
// install. The pack joins the catalog at the next daemon start (gibson#712).
//
// The checks are the ones a catalog pack passes: a strict decode, Validate,
// each predicate compiles against the proof environment, each mapping rule
// compiles against the audit event environment, and Import layers the pack
// onto the core taxonomy and ontology. A pack with the name of an embedded
// catalog pack is refused.
func (s *DomainPackService) ImportDomainPack(
	ctx context.Context, req *tenantv1.ImportDomainPackRequest,
) (*tenantv1.ImportDomainPackResponse, error) {
	id, err := auth.IdentityFromContext(ctx)
	if err != nil || id.Subject == "" {
		return nil, status_grpc.Error(codes.PermissionDenied, "ImportDomainPack: no identity in context")
	}
	pack, err := ontology.DecodePackJSON(req.GetPackJson())
	if err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ImportDomainPack: %v", err)
	}
	if pack.Name == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "ImportDomainPack: the pack has no name")
	}
	if _, embedded := ontology.EmbeddedCatalog().Get(pack.Name); embedded {
		return nil, status_grpc.Errorf(codes.AlreadyExists,
			"ImportDomainPack: %q is an embedded catalog pack, and an import never replaces one", pack.Name)
	}
	if _, err := celenv.LoadDomainPack(&pack); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ImportDomainPack: %v", err)
	}
	if _, err := auditcel.LoadMappingRules(&pack); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ImportDomainPack: %v", err)
	}
	if err := ontology.CheckImport(&pack); err != nil {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "ImportDomainPack: %v", err)
	}
	if err := s.imports.Save(ctx, &pack, id.Subject); err != nil {
		if errors.Is(err, ontology.ErrPackExists) {
			return nil, status_grpc.Errorf(codes.AlreadyExists, "ImportDomainPack: %v", err)
		}
		return nil, status_grpc.Errorf(codes.Internal, "ImportDomainPack: %v", err)
	}
	return &tenantv1.ImportDomainPackResponse{Name: pack.Name, Version: int32Count(pack.Version)}, nil
}
