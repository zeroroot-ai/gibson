package component

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zero-day-ai/gibson/internal/auth"
)

// QueryNodes searches the knowledge graph using hybrid vector + graph scoring.
func (s *ComponentServiceServer) QueryNodes(ctx context.Context, req *componentpb.QueryNodesRequest) (*componentpb.QueryNodesResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	results, err := s.graphrag.QueryNodes(ctx, tenant, req.GetQuery())
	if err != nil {
		s.logger.Error("QueryNodes failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}
	return &componentpb.QueryNodesResponse{Results: results}, nil
}

// StoreNode persists a node in the knowledge graph and returns its assigned ID.
func (s *ComponentServiceServer) StoreNode(ctx context.Context, req *componentpb.StoreNodeRequest) (*componentpb.StoreNodeResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	nodeID, err := s.graphrag.StoreNode(ctx, tenant, req.GetNode())
	if err != nil {
		s.logger.Error("StoreNode failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "store failed: %v", err)
	}
	return &componentpb.StoreNodeResponse{NodeId: nodeID}, nil
}

// FindSimilarAttacks returns attack patterns semantically similar to the given content.
func (s *ComponentServiceServer) FindSimilarAttacks(ctx context.Context, req *componentpb.FindSimilarAttacksRequest) (*componentpb.FindSimilarAttacksResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	resultsJSON, err := s.graphrag.FindSimilarAttacks(ctx, tenant, req.GetContent(), int(req.GetTopK()))
	if err != nil {
		s.logger.Error("FindSimilarAttacks failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "search failed: %v", err)
	}
	return &componentpb.FindSimilarAttacksResponse{ResultsJson: resultsJSON}, nil
}

// GetAttackChains returns multi-hop attack paths from a starting technique.
func (s *ComponentServiceServer) GetAttackChains(ctx context.Context, req *componentpb.GetAttackChainsRequest) (*componentpb.GetAttackChainsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	resultsJSON, err := s.graphrag.GetAttackChains(ctx, tenant, req.GetTechniqueId(), int(req.GetMaxDepth()))
	if err != nil {
		s.logger.Error("GetAttackChains failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "chain query failed: %v", err)
	}
	return &componentpb.GetAttackChainsResponse{ResultsJson: resultsJSON}, nil
}

// FindSimilarFindings returns findings semantically similar to the given finding.
func (s *ComponentServiceServer) FindSimilarFindings(ctx context.Context, req *componentpb.FindSimilarFindingsRequest) (*componentpb.FindSimilarFindingsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	resultsJSON, err := s.graphrag.FindSimilarFindings(ctx, tenant, req.GetFindingId(), int(req.GetTopK()))
	if err != nil {
		s.logger.Error("FindSimilarFindings failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "search failed: %v", err)
	}
	return &componentpb.FindSimilarFindingsResponse{ResultsJson: resultsJSON}, nil
}

// GetRelatedFindings returns findings related to the given finding via graph edges.
func (s *ComponentServiceServer) GetRelatedFindings(ctx context.Context, req *componentpb.GetRelatedFindingsRequest) (*componentpb.GetRelatedFindingsResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "tenant not found in context")
	}
	if s.graphrag == nil {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not configured")
	}
	resultsJSON, err := s.graphrag.GetRelatedFindings(ctx, tenant, req.GetFindingId())
	if err != nil {
		s.logger.Error("GetRelatedFindings failed", "tenant", tenant, "error", err)
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}
	return &componentpb.GetRelatedFindingsResponse{ResultsJson: resultsJSON}, nil
}
