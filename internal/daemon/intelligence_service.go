// Package daemon — intelligence_service.go
//
// # Task 5 — Software Archaeology Findings
//
// ## Source location
//
// The pre-removal IntelligenceService handler lived at:
//   - internal/graphrag/intelligence/ (package) — all five query implementations + service.go
//   - The gRPC adapter was internal/graphrag/intelligence/grpc.go (GRPCServer)
//   - The daemon wired it at internal/daemon/grpc.go:776-782 (before 93d2fcb removal)
//
// ## Pre-removal registration (from git diff 93d2fcb):
//
//	if d.infrastructure != nil && d.infrastructure.intelligenceService != nil {
//	    intelligencepb.RegisterIntelligenceServiceServer(srv,
//	        intelligence.NewGRPCServer(d.infrastructure.intelligenceService))
//	    d.logger.Info(ctx, "registered IntelligenceService gRPC endpoint")
//	} else {
//	    d.logger.Warn(ctx, "IntelligenceService gRPC endpoint not registered: ...")
//	}
//
// ## What was removed in 93d2fcb:
//
//   - Import: "github.com/zero-day-ai/gibson/internal/graphrag/intelligence"
//   - Import: intelligencepb "github.com/zero-day-ai/sdk/api/gen/intelligence/v1"
//   - The registration block above was replaced with a single d.logger.Warn()
//
// ## Query implementations — still exist intact at internal/graphrag/intelligence/:
//
// All five RPCs and their Cypher are intact in the intelligence package.
// The package was NOT deleted — only the gRPC registration in grpc.go was removed.
//
// ### GetRecurringVulnerabilities (internal/graphrag/intelligence/recurring.go)
//
//	Input:  RecurringVulnerabilitiesRequest{Threshold, TimeRange, Severities, TargetTypes, Limit, Offset}
//	Output: GetRecurringVulnerabilitiesResponse{Vulnerabilities[], TotalCount, TimeRange}
//
//	Key Cypher (buildQuery):
//	  MATCH (f:Finding)-[:AFFECTS]->(h:Host)
//	  [WHERE filters]
//	  WITH f.vuln_type AS vuln_type, cve_ids, cwe_ids, severity, created_at, h.id AS host_id
//	  WITH vuln_type, collect(...) AS all_cves, count(*) AS occurrence_count, ...
//	  WHERE occurrence_count >= $threshold
//	  RETURN vuln_type, all_cves, all_cwes, occurrence_count, affected_host_count, ...
//	  ORDER BY occurrence_count DESC SKIP $offset LIMIT $limit
//
// ### GetRemediationMetrics (internal/graphrag/intelligence/remediation.go)
//
//	Input:  GetRemediationMetricsRequest{VulnType, TimeRange, GroupBy}
//	Output: GetRemediationMetricsResponse{Metrics[], OverallRate, OverallMttr, TimeRange, DataLimitations}
//
//	Key Cypher (buildQuery):
//	  MATCH (f:Finding)
//	  OPTIONAL MATCH (f)-[:AFFECTS]->(h:Host)
//	  [WHERE filters]
//	  WITH {group_by_field} AS group_value, count(*) AS total_findings,
//	       sum(CASE WHEN f.status = 'remediated' THEN 1 ELSE 0 END) AS remediated_count, ...
//	  RETURN group_value, total_findings, remediated_count, recurred_count, remediation_times,
//	         remediation_rate, recurrence_rate
//	  ORDER BY total_findings DESC
//
// ### GetAssetRiskScore (internal/graphrag/intelligence/risk.go)
//
//	Input:  GetAssetRiskScoreRequest{AssetId, Algorithm, IncludeHistory, Limit}
//	Output: GetAssetRiskScoreResponse{Assets[], PortfolioRiskScore, PortfolioRiskTier}
//
//	Key Cypher (buildQuery):
//	  MATCH (h:Host) [WHERE h.id = $asset_id]
//	  OPTIONAL MATCH (h)<-[:AFFECTS]-(f:Finding)
//	  OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)-[:EXPOSES]->(e:Endpoint)
//	  WITH h, count/sum of findings by severity, avg_exposure_days, ...
//	  RETURN asset_id, asset_name, critical_findings, high_findings, ...
//	  ORDER BY critical_findings DESC, high_findings DESC LIMIT $limit
//
// ### GetAttackPatterns (internal/graphrag/intelligence/patterns.go)
//
//	Input:  GetAttackPatternsRequest{Technique, TargetType, MinSuccessRate, Limit}
//	Output: GetAttackPatternsResponse{Patterns[], TotalPatterns}
//
//	Key Cypher (buildQuery):
//	  MATCH (m:Mission)-[:PRODUCED]->(f:Finding)
//	  MATCH (m)-[:USED_TECHNIQUE]->(t:Technique)
//	  OPTIONAL MATCH (t)-[:PRECEDES]->(next:Technique)<-[:USED_TECHNIQUE]-(m)
//	  [WHERE technique/target_type filters]
//	  WITH t.technique, mitre_id, mitre_name, collect(next), finding_count, mission_count, ...
//	  WITH ..., toFloat(finding_count) / mission_count AS success_rate
//	  WHERE success_rate >= $min_success_rate
//	  RETURN technique, mitre_id, ..., success_rate, target_types, sample_missions
//	  ORDER BY success_rate DESC LIMIT $limit
//
// ### GetSimilarTargets (internal/graphrag/intelligence/similarity.go)
//
//	Input:  GetSimilarTargetsRequest{TargetId, K, Features}
//	Output: GetSimilarTargetsResponse{ReferenceTargetId, SimilarTargets[], FeaturesUsed}
//
//	Key Cypher (getTargetData + getCandidateTargets — similarity is computed in Go):
//	  MATCH (h:Host {id: $target_id})
//	  OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)-[:USES_TECHNOLOGY]->(tech:Technology)
//	  OPTIONAL MATCH (h)<-[:AFFECTS]-(f:Finding)<-[:PRODUCED]-(m:Mission)-[:USED_TECHNIQUE]->(t:Technique)
//	  RETURN h.id, hostname, technologies, ports, services, vuln_types, finding_ids, techniques
//
// ## FGA annotations (verified from core/sdk/api/proto/intelligence/v1/intelligence.proto):
//
//	All five RPCs carry:
//	  option (gibson.auth.v1.authz) = {
//	    relation: "member"
//	    object_type: "tenant"
//	    object_deriver: "tenant_from_identity"
//	    allowed_identities: 3  // USER | SERVICE
//	  };
//
//	The annotations SURVIVED the 93d2fcb removal (the proto file was not touched).
//	The authz registry already enforces these annotations via the FGA interceptor.
//	Re-registration restores FGA enforcement automatically — no new authz work needed.
//
// ## Implementation strategy (Task 6):
//
// The intelligence package (internal/graphrag/intelligence/) holds all Cypher logic
// in driver-backed query types. Rather than duplicate the Cypher here, we add a
// SessionService that wraps a neo4j.SessionWithContext and delegates to the existing
// query implementations via their build+execute pattern on the provided session.
// The intelligenceServer struct below wires pool resolution → per-tenant session →
// SessionService → existing gRPC translation layer (GRPCServer.Get*).

package daemon

import (
	"context"
	"log/slog"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag/intelligence"
	intelligencepb "github.com/zero-day-ai/sdk/api/gen/intelligence/v1"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// intelligenceServer implements intelligencepb.IntelligenceServiceServer using
// the deferred-pool pattern. Each RPC call resolves the calling tenant from ctx,
// acquires a per-tenant Neo4j session from the pool, and delegates to the
// existing intelligence package query implementations via a SessionService.
//
// The server is registered at gRPC construction time (before pool init) via a
// PoolGetter closure. If the pool is not yet ready, RPCs return codes.Unavailable.
type intelligenceServer struct {
	intelligencepb.UnimplementedIntelligenceServiceServer

	poolGetter func() datapool.Pool
	logger     *slog.Logger
}

// NewIntelligenceServer constructs an intelligenceServer.
// poolGetter must be non-nil; it is called per-request to obtain the live pool.
func NewIntelligenceServer(poolGetter func() datapool.Pool, logger *slog.Logger) *intelligenceServer {
	if poolGetter == nil {
		panic("intelligence server: poolGetter cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &intelligenceServer{
		poolGetter: poolGetter,
		logger:     logger,
	}
}

// acquireSession is the common preamble for all five RPC handlers:
//  1. Read tenant from ctx → FailedPrecondition if missing.
//  2. Get pool from getter → Unavailable if nil.
//  3. Acquire per-tenant conn → MapPoolError on failure.
//
// Returns the session and a release func. Callers MUST defer the release func.
func (s *intelligenceServer) acquireSession(ctx context.Context) (neo4j.SessionWithContext, func(), error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, func() {}, status.Error(codes.FailedPrecondition, "no tenant in context")
	}

	pool := s.poolGetter()
	if pool == nil {
		return nil, func() {}, status.Error(codes.Unavailable, "data-plane pool not yet ready")
	}

	conn, err := pool.For(ctx, tenant)
	if err != nil {
		return nil, func() {}, datapool.MapPoolError(err)
	}

	return conn.Neo4j, conn.Release, nil
}

// newSvc constructs a per-request intelligence.SessionService from a live session.
// The service has no circuit breaker or cache — lifecycle is scoped to a single RPC.
func newSvc(session neo4j.SessionWithContext, logger *slog.Logger) *intelligence.SessionService {
	return intelligence.NewSessionService(session, logger)
}

// GetRecurringVulnerabilities implements IntelligenceServiceServer.
func (s *intelligenceServer) GetRecurringVulnerabilities(
	ctx context.Context,
	req *intelligencepb.GetRecurringVulnerabilitiesRequest,
) (*intelligencepb.GetRecurringVulnerabilitiesResponse, error) {
	session, release, err := s.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	opts := sdkgraphrag.RecurringVulnOpts{
		Threshold:   int(req.GetThreshold()),
		TargetTypes: req.GetTargetTypes(),
		Limit:       int(req.GetLimit()),
		Offset:      int(req.GetOffset()),
	}
	if tr := req.GetTimeRange(); tr != nil {
		opts.TimeRange = &sdkgraphrag.TimeRange{
			Start: tr.GetStart().AsTime(),
			End:   tr.GetEnd().AsTime(),
		}
	}
	for _, sev := range req.GetSeverities() {
		opts.Severities = append(opts.Severities, protoSeverityToSDKIntel(sev))
	}

	result, err := newSvc(session, s.logger).GetRecurringVulnerabilities(ctx, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &intelligencepb.GetRecurringVulnerabilitiesResponse{
		TotalCount: int32(result.TotalCount),
	}
	if !result.TimeRange.Start.IsZero() || !result.TimeRange.End.IsZero() {
		resp.TimeRange = &intelligencepb.TimeRange{
			Start: timestamppb.New(result.TimeRange.Start),
			End:   timestamppb.New(result.TimeRange.End),
		}
	}
	for _, v := range result.Vulnerabilities {
		pv := &intelligencepb.RecurringVulnerability{
			VulnType:          v.VulnType,
			CveIds:            v.CVEIDs,
			CweIds:            v.CWEIDs,
			OccurrenceCount:   int32(v.OccurrenceCount),
			AffectedHostCount: int32(v.AffectedHostCount),
			SampleHosts:       v.SampleHosts,
		}
		if !v.FirstSeen.IsZero() {
			pv.FirstSeen = timestamppb.New(v.FirstSeen)
		}
		if !v.LastSeen.IsZero() {
			pv.LastSeen = timestamppb.New(v.LastSeen)
		}
		if len(v.SeverityDistribution) > 0 {
			pv.SeverityDistribution = make(map[string]int32, len(v.SeverityDistribution))
			for k, c := range v.SeverityDistribution {
				pv.SeverityDistribution[string(k)] = int32(c)
			}
		}
		resp.Vulnerabilities = append(resp.Vulnerabilities, pv)
	}
	return resp, nil
}

// GetRemediationMetrics implements IntelligenceServiceServer.
func (s *intelligenceServer) GetRemediationMetrics(
	ctx context.Context,
	req *intelligencepb.GetRemediationMetricsRequest,
) (*intelligencepb.GetRemediationMetricsResponse, error) {
	session, release, err := s.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	opts := sdkgraphrag.RemediationOpts{
		VulnType: req.GetVulnType(),
		GroupBy:  req.GetGroupBy(),
	}
	if tr := req.GetTimeRange(); tr != nil {
		opts.TimeRange = &sdkgraphrag.TimeRange{
			Start: tr.GetStart().AsTime(),
			End:   tr.GetEnd().AsTime(),
		}
	}

	result, err := newSvc(session, s.logger).GetRemediationMetrics(ctx, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &intelligencepb.GetRemediationMetricsResponse{
		OverallRate:     result.OverallRate,
		OverallMttr:     result.OverallMTTR,
		DataLimitations: result.DataLimitations,
	}
	if !result.TimeRange.Start.IsZero() || !result.TimeRange.End.IsZero() {
		resp.TimeRange = &intelligencepb.TimeRange{
			Start: timestamppb.New(result.TimeRange.Start),
			End:   timestamppb.New(result.TimeRange.End),
		}
	}
	for _, m := range result.Metrics {
		resp.Metrics = append(resp.Metrics, &intelligencepb.RemediationMetric{
			GroupKey:           m.GroupKey,
			GroupValue:         m.GroupValue,
			RemediationRate:    m.RemediationRate,
			Mttr:               m.MTTR,
			RecurrenceRate:     m.RecurrenceRate,
			TotalFindings:      int32(m.TotalFindings),
			RemediatedFindings: int32(m.RemediatedFindings),
			TrendVsPrevious:    m.TrendVsPrevious,
		})
	}
	return resp, nil
}

// GetAssetRiskScore implements IntelligenceServiceServer.
func (s *intelligenceServer) GetAssetRiskScore(
	ctx context.Context,
	req *intelligencepb.GetAssetRiskScoreRequest,
) (*intelligencepb.GetAssetRiskScoreResponse, error) {
	session, release, err := s.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	opts := sdkgraphrag.RiskScoreOpts{
		AssetID:        req.GetAssetId(),
		Algorithm:      req.GetAlgorithm(),
		IncludeHistory: req.GetIncludeHistory(),
		Limit:          int(req.GetLimit()),
	}

	result, err := newSvc(session, s.logger).GetAssetRiskScore(ctx, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &intelligencepb.GetAssetRiskScoreResponse{
		PortfolioRiskScore: result.PortfolioRiskScore,
		PortfolioRiskTier:  result.PortfolioRiskTier,
	}
	for _, a := range result.Assets {
		pa := &intelligencepb.AssetRiskScore{
			AssetId:         a.AssetID,
			AssetName:       a.AssetName,
			Score:           a.Score,
			Tier:            a.Tier,
			TrendVsPrevious: a.TrendVsPrevious,
			Recommendations: a.Recommendations,
		}
		for _, f := range a.Factors {
			pa.Factors = append(pa.Factors, &intelligencepb.RiskFactor{
				Name:        f.Name,
				Weight:      f.Weight,
				Value:       f.Value,
				Description: f.Description,
			})
		}
		for _, h := range a.HistoricalScores {
			ph := &intelligencepb.HistoricalRiskScore{Score: h.Score, Tier: h.Tier}
			if !h.Date.IsZero() {
				ph.Date = timestamppb.New(h.Date)
			}
			pa.HistoricalScores = append(pa.HistoricalScores, ph)
		}
		resp.Assets = append(resp.Assets, pa)
	}
	return resp, nil
}

// GetAttackPatterns implements IntelligenceServiceServer.
func (s *intelligenceServer) GetAttackPatterns(
	ctx context.Context,
	req *intelligencepb.GetAttackPatternsRequest,
) (*intelligencepb.GetAttackPatternsResponse, error) {
	session, release, err := s.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	opts := sdkgraphrag.PatternOpts{
		Technique:      req.GetTechnique(),
		TargetType:     req.GetTargetType(),
		MinSuccessRate: req.GetMinSuccessRate(),
		Limit:          int(req.GetLimit()),
	}

	result, err := newSvc(session, s.logger).GetAttackPatterns(ctx, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &intelligencepb.GetAttackPatternsResponse{
		TotalPatterns: int32(result.TotalPatterns),
	}
	for _, pat := range result.Patterns {
		pp := &intelligencepb.AttackPattern{
			PatternId:             pat.PatternID,
			SuccessRate:           pat.SuccessRate,
			OccurrenceCount:       int32(pat.OccurrenceCount),
			TargetCharacteristics: pat.TargetCharacteristics,
			SampleMissions:        pat.SampleMissions,
			Confidence:            pat.Confidence,
		}
		for _, tc := range pat.TechniqueChain {
			pp.TechniqueChain = append(pp.TechniqueChain, &intelligencepb.TechniqueInChain{
				Technique: tc.Technique,
				MitreId:   tc.MitreID,
				MitreName: tc.MitreName,
				Position:  int32(tc.Position),
			})
		}
		resp.Patterns = append(resp.Patterns, pp)
	}
	return resp, nil
}

// GetSimilarTargets implements IntelligenceServiceServer.
func (s *intelligenceServer) GetSimilarTargets(
	ctx context.Context,
	req *intelligencepb.GetSimilarTargetsRequest,
) (*intelligencepb.GetSimilarTargetsResponse, error) {
	session, release, err := s.acquireSession(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	opts := sdkgraphrag.SimilarTargetsOpts{
		TargetID: req.GetTargetId(),
		K:        int(req.GetK()),
		Features: req.GetFeatures(),
	}

	result, err := newSvc(session, s.logger).GetSimilarTargets(ctx, opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	resp := &intelligencepb.GetSimilarTargetsResponse{
		ReferenceTargetId: result.ReferenceTargetID,
		FeaturesUsed:      result.FeaturesUsed,
	}
	for _, st := range result.SimilarTargets {
		pst := &intelligencepb.SimilarTarget{
			TargetId:              st.TargetID,
			TargetName:            st.TargetName,
			SimilarityScore:       st.SimilarityScore,
			SuccessfulFindings:    st.SuccessfulFindings,
			RecommendedTechniques: st.RecommendedTechniques,
		}
		if len(st.MatchingFeatures) > 0 {
			pst.MatchingFeatures = make(map[string]*intelligencepb.FeatureMatch, len(st.MatchingFeatures))
			for k, fm := range st.MatchingFeatures {
				pst.MatchingFeatures[k] = &intelligencepb.FeatureMatch{
					Feature:       fm.Feature,
					Overlap:       fm.Overlap,
					MatchedValues: fm.MatchedValues,
				}
			}
		}
		resp.SimilarTargets = append(resp.SimilarTargets, pst)
	}
	return resp, nil
}

// protoSeverityToSDKIntel converts the proto Severity enum to the SDK severity string.
// Mirrors intelligence.GRPCServer.protoSeverityToSDK (unexported there; duplicated here
// to avoid a cross-package dependency on an unexported function).
func protoSeverityToSDKIntel(s intelligencepb.Severity) sdkgraphrag.Severity {
	switch s {
	case intelligencepb.Severity_SEVERITY_CRITICAL:
		return sdkgraphrag.SeverityCritical
	case intelligencepb.Severity_SEVERITY_HIGH:
		return sdkgraphrag.SeverityHigh
	case intelligencepb.Severity_SEVERITY_MEDIUM:
		return sdkgraphrag.SeverityMedium
	case intelligencepb.Severity_SEVERITY_LOW:
		return sdkgraphrag.SeverityLow
	case intelligencepb.Severity_SEVERITY_INFO:
		return sdkgraphrag.SeverityInfo
	case intelligencepb.Severity_SEVERITY_INFORMATIONAL:
		return sdkgraphrag.SeverityInformational
	default:
		return sdkgraphrag.Severity("")
	}
}

// compile-time interface check
var _ intelligencepb.IntelligenceServiceServer = (*intelligenceServer)(nil)
