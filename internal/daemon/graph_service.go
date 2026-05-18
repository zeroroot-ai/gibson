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
// GetGraphSummary uses an in-process per-tenant cache (60s TTL) to avoid
// repeated Neo4j queries for LLM-context calls (Task 6).
//
// GetGraphContext soft-fails on missing node or NotProvisioned — it never
// returns a gRPC error, only an empty response (Req 5.2).
//
// Spec: dashboard-knowledge-graph (Phase 2, Tasks 5 and 10).
// Spec: dashboard-neo4j-client-removal (Phase 2, Tasks 5 and 6).
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const graphQueryTimeout = 5 * time.Second

// summaryCacheEntry holds a cached GetGraphSummaryResponse with its age.
type summaryCacheEntry struct {
	result   *graphpb.GetGraphSummaryResponse
	cachedAt time.Time
}

const summaryCacheTTL = 60 * time.Second

// graphServer implements graphpb.GraphServiceServer.
// It uses the deferred-pool pattern: poolGetter is called per-request to
// obtain the live pool (safe to call before pool initialisation completes).
type graphServer struct {
	graphpb.UnimplementedGraphServiceServer

	poolGetter   func() datapool.Pool
	logger       *slog.Logger
	bus          *graph.Bus // wired in Task 10 via NewGraphServer; nil until then
	summaryCache sync.Map   // key: tenant ID string, value: *summaryCacheEntry
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
		Paths:          paths,
		Nodes:          nodes,
		Edges:          edges,
		TruncatedPaths: truncated,
	}, nil
}

// GetFindingCounts implements GraphServiceServer.
// Returns finding counts grouped by severity or category.
func (s *graphServer) GetFindingCounts(
	ctx context.Context,
	req *graphpb.GetFindingCountsRequest,
) (*graphpb.GetFindingCountsResponse, error) {
	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	buckets, err := q.FindingCounts(qctx, tenant, req.GetGroupBy(), req.GetTimeWindowSeconds())
	if err != nil {
		s.logger.WarnContext(ctx, "GetFindingCounts: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "finding counts query failed: %v", err)
	}

	pbBuckets := make([]*graphpb.CountBucket, 0, len(buckets))
	for _, b := range buckets {
		pbBuckets = append(pbBuckets, &graphpb.CountBucket{
			Label: b.Label,
			Count: b.Count,
		})
	}
	return &graphpb.GetFindingCountsResponse{Buckets: pbBuckets}, nil
}

// GetFindingTimeSeries implements GraphServiceServer.
// Returns daily finding counts for the past N days (padded, default 30, max 365).
func (s *graphServer) GetFindingTimeSeries(
	ctx context.Context,
	req *graphpb.GetFindingTimeSeriesRequest,
) (*graphpb.GetFindingTimeSeriesResponse, error) {
	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	days := req.GetDays()
	if days == 0 {
		days = graph.DefaultTimeSeriesDays
	}
	if days > graph.MaxTimeSeriesDays {
		days = graph.MaxTimeSeriesDays
	}

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	points, err := q.FindingTimeSeries(qctx, tenant, days)
	if err != nil {
		s.logger.WarnContext(ctx, "GetFindingTimeSeries: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "finding time series query failed: %v", err)
	}

	return &graphpb.GetFindingTimeSeriesResponse{Points: points}, nil
}

// GetGraphStats implements GraphServiceServer.
// Returns per-label node counts, total nodes/edges, and max last_write_at.
func (s *graphServer) GetGraphStats(
	ctx context.Context,
	_ *graphpb.GetGraphStatsRequest,
) (*graphpb.GetGraphStatsResponse, error) {
	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	stats, err := q.GraphStats(qctx, tenant)
	if err != nil {
		s.logger.WarnContext(ctx, "GetGraphStats: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "graph stats query failed: %v", err)
	}

	pbByLabel := make([]*graphpb.NodeCountByLabel, 0, len(stats.ByLabel))
	for _, nb := range stats.ByLabel {
		pbByLabel = append(pbByLabel, &graphpb.NodeCountByLabel{
			Label: nb.Label,
			Count: nb.Count,
		})
	}

	resp := &graphpb.GetGraphStatsResponse{
		ByLabel:    pbByLabel,
		TotalNodes: stats.TotalNodes,
		TotalEdges: stats.TotalEdges,
	}
	if !stats.LastWriteAt.IsZero() {
		resp.LastWriteAt = timestamppb.New(stats.LastWriteAt)
	}
	return resp, nil
}

// GetGraphSummary implements GraphServiceServer.
// Returns an LLM-friendly text summary with a 60s per-tenant server-side cache.
func (s *graphServer) GetGraphSummary(
	ctx context.Context,
	_ *graphpb.GetGraphSummaryRequest,
) (*graphpb.GetGraphSummaryResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, status.Error(codes.PermissionDenied, "missing tenant in context")
	}

	// --- Cache lookup (before pool acquisition) ---
	cacheKey := tenant.String()
	if v, hit := s.summaryCache.Load(cacheKey); hit {
		entry := v.(*summaryCacheEntry)
		if time.Since(entry.cachedAt) < summaryCacheTTL {
			return entry.result, nil
		}
	}

	// --- Cache miss: acquire conn and compute ---
	conn, err := func() (*datapool.Conn, error) {
		pool := s.poolGetter()
		if pool == nil {
			return nil, status.Error(codes.Unavailable, "data-plane pool not yet ready")
		}
		c, err := pool.For(ctx, tenant)
		if err != nil {
			return nil, datapool.MapPoolError(err)
		}
		return c, nil
	}()
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	summary, err := q.GraphSummary(qctx, tenant)
	if err != nil {
		s.logger.WarnContext(ctx, "GetGraphSummary: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "graph summary query failed: %v", err)
	}

	resp := &graphpb.GetGraphSummaryResponse{
		Summary: summary.Summary,
		Stats: &graphpb.GraphSummaryStats{
			Hosts:           summary.Stats.Hosts,
			Services:        summary.Stats.Services,
			Findings:        summary.Stats.Findings,
			Vulnerabilities: summary.Stats.Vulnerabilities,
			Missions:        summary.Stats.Missions,
		},
	}

	s.summaryCache.Store(cacheKey, &summaryCacheEntry{
		result:   resp,
		cachedAt: time.Now(),
	})
	return resp, nil
}

// GetGraphContext implements GraphServiceServer.
// Returns a focus node and its neighborhood for chatbot prompts.
// Soft-fails on missing node or NotProvisioned — never returns a gRPC error
// for those cases, only an empty response (Req 5.2).
func (s *graphServer) GetGraphContext(
	ctx context.Context,
	req *graphpb.GetGraphContextRequest,
) (*graphpb.GetGraphContextResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, status.Error(codes.PermissionDenied, "missing tenant in context")
	}

	pool := s.poolGetter()
	if pool == nil {
		// Soft-fail: pool not ready → return empty context, no error.
		return &graphpb.GetGraphContextResponse{}, nil
	}

	conn, err := pool.For(ctx, tenant)
	if err != nil {
		// Soft-fail for NotProvisioned (Req 5.2); propagate other pool errors normally.
		var npErr *datapool.NotProvisionedError
		if errors.As(err, &npErr) {
			return &graphpb.GetGraphContextResponse{}, nil
		}
		return nil, datapool.MapPoolError(err)
	}
	defer conn.Release()

	hops := req.GetHops()
	if hops == 0 {
		hops = graph.DefaultContextHops
	}
	if hops > graph.MaxContextHops {
		hops = graph.MaxContextHops
	}
	maxNodes := req.GetMaxNodes()
	if maxNodes == 0 {
		maxNodes = graph.DefaultContextMaxNodes
	}
	if maxNodes > graph.MaxContextMaxNodes {
		maxNodes = graph.MaxContextMaxNodes
	}

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	gctx, err := q.GraphContext(qctx, tenant, req.GetNodeId(), hops, maxNodes)
	if err != nil {
		// Soft-fail on query error (e.g. node vanished mid-request).
		s.logger.WarnContext(ctx, "GetGraphContext: query failed (soft-fail)",
			slog.String("tenant", tenant.String()),
			slog.String("node_id", req.GetNodeId()),
			slog.String("error", err.Error()),
		)
		return &graphpb.GetGraphContextResponse{}, nil
	}

	return &graphpb.GetGraphContextResponse{
		FocusNode: gctx.FocusNode,
		Neighbors: gctx.Neighbors,
		Summary:   gctx.Summary,
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
// GetFindings implements GraphServiceServer.
// Returns a paginated, filtered list of finding + vulnerability nodes for the
// requesting tenant. Spec: dashboard-neo4j-crud-removal (Task 5).
func (s *graphServer) GetFindings(
	ctx context.Context,
	req *graphpb.GetFindingsRequest,
) (*graphpb.GetFindingsResponse, error) {
	tenant, conn, release, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	// Clamp limit.
	limit := req.GetLimit()
	if limit == 0 {
		limit = graph.DefaultFindingsLimit
	}
	if limit > graph.MaxFindingsLimit {
		limit = graph.MaxFindingsLimit
	}

	qctx, cancel := context.WithTimeout(ctx, graphQueryTimeout)
	defer cancel()

	filters := graph.FindingsFilters{
		Severity:  req.GetSeverityFilter(),
		Category:  req.GetCategoryFilter(),
		MissionID: req.GetMissionId(),
		Search:    req.GetSearch(),
		Limit:     limit,
		Offset:    req.GetOffset(),
	}

	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(conn.Neo4j))
	records, total, err := q.Findings(qctx, tenant, filters)
	if err != nil {
		s.logger.WarnContext(ctx, "GetFindings: query failed",
			slog.String("tenant", tenant.String()),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "findings query failed: %v", err)
	}

	// Marshal to proto Finding.
	pbFindings := make([]*graphpb.Finding, 0, len(records))
	for _, r := range records {
		pbf := &graphpb.Finding{
			Id:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Type:        r.Type,
			Severity:    r.Severity,
			MissionId:   r.MissionID,
			Properties:  r.Properties,
			Labels:      r.Labels,
		}
		if !r.CreatedAt.IsZero() {
			pbf.CreatedAt = timestamppb.New(r.CreatedAt)
		}
		pbFindings = append(pbFindings, pbf)
	}

	offset := req.GetOffset()
	truncated := total > uint64(offset)+uint64(len(pbFindings))

	return &graphpb.GetFindingsResponse{
		Findings:  pbFindings,
		Total:     total,
		Truncated: truncated,
	}, nil
}

var _ graphpb.GraphServiceServer = (*graphServer)(nil)
