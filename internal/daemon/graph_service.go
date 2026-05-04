// Package daemon — graph_service.go
//
// graphServer implements graphpb.GraphServiceServer using the deferred-pool
// pattern established in intelligence_service.go. Each RPC call:
//  1. Reads tenant from ctx (PermissionDenied if absent).
//  2. Resolves the live pool via poolGetter and calls pool.For(ctx, tenant).
//  3. Constructs a per-call DashboardQueries from conn.Neo4j.
//  4. Executes the query under a 5-second context timeout.
//  5. Marshals Neo4j results to proto and returns.
//
// WatchGraphUpdates subscribes to the in-process graph bus (graphbuspkg.Bus).
// The bus is wired in Task 10; until then it is nil and the RPC returns
// codes.Unimplemented (replaced with full implementation in Task 10).
//
// Spec: dashboard-knowledge-graph (Phase 2, Tasks 5 and 10).
package daemon

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
)

const graphQueryTimeout = 5 * time.Second

// graphServer implements graphpb.GraphServiceServer.
// It uses the deferred-pool pattern: poolGetter is called per-request to
// obtain the live pool (safe to call before pool initialisation completes).
type graphServer struct {
	graphpb.UnimplementedGraphServiceServer

	poolGetter func() datapool.Pool
	logger     *slog.Logger
	bus        *graph.Bus // wired in Task 10 via NewGraphServer; nil until then
}

// NewGraphServer constructs a graphServer.
// poolGetter must not be nil. logger may be nil (defaults to slog.Default()).
// bus may be nil; WatchGraphUpdates returns Unimplemented until it is set.
func NewGraphServer(
	poolGetter func() datapool.Pool,
	logger *slog.Logger,
	bus *graph.Bus,
) *graphServer {
	if poolGetter == nil {
		panic("graph server: poolGetter cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &graphServer{
		poolGetter: poolGetter,
		logger:     logger,
		bus:        bus,
	}
}

// acquireConn is the common preamble:
//  1. Read tenant from ctx → PermissionDenied if missing.
//  2. Get pool → Unavailable if nil.
//  3. pool.For(ctx, tenant) → MapPoolError on failure.
//
// Returns (tenant, conn, releaseFunc, error). Callers MUST defer the release.
func (s *graphServer) acquireConn(ctx context.Context) (auth.TenantID, *datapool.Conn, func(), error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return auth.TenantID{}, nil, func() {}, status.Error(codes.PermissionDenied, "missing tenant in context")
	}

	pool := s.poolGetter()
	if pool == nil {
		return auth.TenantID{}, nil, func() {}, status.Error(codes.Unavailable, "data-plane pool not yet ready")
	}

	conn, err := pool.For(ctx, tenant)
	if err != nil {
		return auth.TenantID{}, nil, func() {}, datapool.MapPoolError(err)
	}

	return tenant, conn, conn.Release, nil
}

// GetTenantGraph implements GraphServiceServer.
func (s *graphServer) GetTenantGraph(
	ctx context.Context,
	req *graphpb.GetTenantGraphRequest,
) (*graphpb.GetTenantGraphResponse, error) {
	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	limit := req.GetLimit()
	if limit == 0 {
		limit = graph.DefaultGraphLimit
	}
	if limit > graph.MaxGraphLimit {
		limit = graph.MaxGraphLimit
	}

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	nodes, edges, truncated, totalCount, err := q.GetFullGraph(qctx, tenant, limit, req.GetIncludeLabels())
	if err != nil {
		s.logger.WarnContext(ctx, "GetTenantGraph: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "graph query failed: %v", err)
	}

	return &graphpb.GetTenantGraphResponse{
		Nodes:          nodes,
		Edges:          edges,
		Truncated:      truncated,
		TotalNodeCount: totalCount,
	}, nil
}

// GetMissionGraph implements GraphServiceServer.
func (s *graphServer) GetMissionGraph(
	ctx context.Context,
	req *graphpb.GetMissionGraphRequest,
) (*graphpb.GetMissionGraphResponse, error) {
	if req.GetMissionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "mission_id is required")
	}

	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	nodes, edges, err := q.GetMissionGraph(qctx, tenant, req.GetMissionId())
	if err != nil {
		s.logger.WarnContext(ctx, "GetMissionGraph: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("mission_id", req.GetMissionId()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "graph query failed: %v", err)
	}

	return &graphpb.GetMissionGraphResponse{
		Nodes: nodes,
		Edges: edges,
	}, nil
}

// QueryPaths implements GraphServiceServer.
func (s *graphServer) QueryPaths(
	ctx context.Context,
	req *graphpb.QueryPathsRequest,
) (*graphpb.QueryPathsResponse, error) {
	if req.GetFromNodeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "from_node_id is required")
	}
	toNodeID := req.GetToNodeId()
	toNodeKind := req.GetToNodeKind()
	if toNodeID == "" && toNodeKind == "" {
		return nil, status.Error(codes.InvalidArgument, "one of to_node_id or to_node_kind is required")
	}
	if toNodeID != "" && toNodeKind != "" {
		return nil, status.Error(codes.InvalidArgument, "only one of to_node_id or to_node_kind may be set")
	}

	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	maxDepth := req.GetMaxDepth()
	if maxDepth == 0 {
		maxDepth = graph.DefaultPathDepth
	}
	if maxDepth > graph.MaxPathDepth {
		maxDepth = graph.MaxPathDepth
	}

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	paths, nodes, edges, truncated, err := q.QueryPaths(qctx, tenant, req.GetFromNodeId(), toNodeID, toNodeKind, maxDepth)
	if err != nil {
		s.logger.WarnContext(ctx, "QueryPaths: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("from", req.GetFromNodeId()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "path query failed: %v", err)
	}

	return &graphpb.QueryPathsResponse{
		Paths:         paths,
		Nodes:         nodes,
		Edges:         edges,
		TruncatedPaths: truncated,
	}, nil
}

// WatchGraphUpdates implements GraphServiceServer.
// Full implementation in Task 10. Until the bus is wired this returns
// codes.Unimplemented so callers can fall back to polling immediately.
func (s *graphServer) WatchGraphUpdates(
	req *graphpb.WatchGraphUpdatesRequest,
	stream graphpb.GraphService_WatchGraphUpdatesServer,
) error {
	if s.bus == nil {
		return status.Error(codes.Unimplemented, "WatchGraphUpdates: update bus not yet wired")
	}

	ctx := stream.Context()
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return status.Error(codes.PermissionDenied, "missing tenant in context")
	}

	sub := s.bus.Subscribe(tenant)
	defer s.bus.Unsubscribe(sub)

	for {
		select {
		case <-ctx.Done():
			return nil
		case update, open := <-sub.Ch():
			if !open {
				return nil
			}
			if err := stream.Send(update); err != nil {
				st, _ := status.FromError(err)
				if st.Code() == codes.ResourceExhausted {
					s.logger.WarnContext(ctx, "WatchGraphUpdates: slow client; closing stream",
						slog.String("tenant", tenant.String()),
					)
				}
				return err
			}
		}
	}
}

// compile-time interface check.
var _ graphpb.GraphServiceServer = (*graphServer)(nil)
