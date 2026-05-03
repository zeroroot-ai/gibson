// Package intelligence — session_service.go
//
// SessionService wraps a pre-opened neo4j.SessionWithContext and implements
// the same five intelligence queries as Service, but without constructing new
// sessions or managing a driver. This is the per-request, per-tenant variant
// used by the daemon's IntelligenceService gRPC handlers (intelligence_service.go).
//
// Lifecycle: one SessionService per gRPC call. The session is acquired from the
// per-tenant pool connection before the handler calls NewSessionService; the
// pool connection's Release() is deferred by the handler. SessionService must
// NOT close the session — the pool conn owns the lifecycle.
package intelligence

import (
	"context"
	"log/slog"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// SessionService runs the five intelligence queries on a pre-opened session.
// It has no circuit breaker, cache, or driver dependency — all of those are
// caller concerns. Each Execute call runs directly on the provided session.
type SessionService struct {
	session neo4j.SessionWithContext
	logger  *slog.Logger

	// re-use the existing query implementations, redirected to the shared session.
	recurring   *sessionRecurring
	remediation *sessionRemediation
	risk        *sessionRisk
	patterns    *sessionPatterns
	similarity  *sessionSimilarity
}

// NewSessionService constructs a SessionService for a single per-tenant session.
// The session must already be open. The caller is responsible for closing/releasing
// it via the pool conn's Release() — SessionService never calls session.Close().
func NewSessionService(session neo4j.SessionWithContext, logger *slog.Logger) *SessionService {
	if logger == nil {
		logger = slog.Default()
	}
	return &SessionService{
		session:     session,
		logger:      logger,
		recurring:   &sessionRecurring{session: session},
		remediation: &sessionRemediation{session: session},
		risk:        &sessionRisk{session: session},
		patterns:    &sessionPatterns{session: session},
		similarity:  &sessionSimilarity{session: session},
	}
}

// GetRecurringVulnerabilities delegates to the session-backed recurring query.
func (s *SessionService) GetRecurringVulnerabilities(ctx context.Context, opts sdkgraphrag.RecurringVulnOpts) (*sdkgraphrag.RecurringVulnResult, error) {
	return s.recurring.Execute(ctx, opts)
}

// GetRemediationMetrics delegates to the session-backed remediation query.
func (s *SessionService) GetRemediationMetrics(ctx context.Context, opts sdkgraphrag.RemediationOpts) (*sdkgraphrag.RemediationResult, error) {
	return s.remediation.Execute(ctx, opts)
}

// GetAssetRiskScore delegates to the session-backed risk calculator.
func (s *SessionService) GetAssetRiskScore(ctx context.Context, opts sdkgraphrag.RiskScoreOpts) (*sdkgraphrag.RiskScoreResult, error) {
	return s.risk.Execute(ctx, opts)
}

// GetAttackPatterns delegates to the session-backed pattern analyzer.
func (s *SessionService) GetAttackPatterns(ctx context.Context, opts sdkgraphrag.PatternOpts) (*sdkgraphrag.PatternResult, error) {
	return s.patterns.Execute(ctx, opts)
}

// GetSimilarTargets delegates to the session-backed similarity finder.
func (s *SessionService) GetSimilarTargets(ctx context.Context, opts sdkgraphrag.SimilarTargetsOpts) (*sdkgraphrag.SimilarTargetsResult, error) {
	return s.similarity.Execute(ctx, opts)
}

// ─────────────────────────────────────────────────────────────────────────────
// Session-backed query implementations
// Each type mirrors the driver-backed counterpart but holds a session directly.
// ─────────────────────────────────────────────────────────────────────────────

// sessionRecurring is a session-backed RecurringVulnerabilityQuery.
type sessionRecurring struct {
	session neo4j.SessionWithContext
	// Embed the driver-backed query for its buildQuery + parseVulnerability helpers.
	// We construct it with a nil driver — only the helper methods are called.
	helper RecurringVulnerabilityQuery
}

// Execute runs the recurring vulnerability query on the shared session.
func (q *sessionRecurring) Execute(ctx context.Context, opts sdkgraphrag.RecurringVulnOpts) (*sdkgraphrag.RecurringVulnResult, error) {
	if opts.Threshold <= 0 {
		opts.Threshold = 3
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	cypher, params := q.helper.buildQuery(opts)

	result, err := q.session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var vulns []sdkgraphrag.RecurringVulnerability
		for records.Next(ctx) {
			vulns = append(vulns, q.helper.parseVulnerability(records.Record()))
		}
		if err := records.Err(); err != nil {
			return nil, err
		}
		return vulns, nil
	})
	if err != nil {
		return nil, err
	}

	vulns := result.([]sdkgraphrag.RecurringVulnerability)
	timeRange := sdkgraphrag.TimeRange{}
	if opts.TimeRange != nil {
		timeRange = *opts.TimeRange
	} else {
		timeRange = sdkgraphrag.TimeRange{Start: time.Now().AddDate(0, -3, 0), End: time.Now()}
	}
	return &sdkgraphrag.RecurringVulnResult{
		Vulnerabilities: vulns,
		TotalCount:      len(vulns),
		TimeRange:       timeRange,
	}, nil
}

// sessionRemediation is a session-backed RemediationMetricsQuery.
type sessionRemediation struct {
	session neo4j.SessionWithContext
	helper  RemediationMetricsQuery
}

// Execute runs the remediation metrics query on the shared session.
func (q *sessionRemediation) Execute(ctx context.Context, opts sdkgraphrag.RemediationOpts) (*sdkgraphrag.RemediationResult, error) {
	cypher, params := q.helper.buildQuery(opts)

	result, err := q.session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var metrics []sdkgraphrag.RemediationMetric
		for records.Next(ctx) {
			metrics = append(metrics, q.helper.parseMetric(records.Record(), opts.GroupBy))
		}
		if err := records.Err(); err != nil {
			return nil, err
		}
		return metrics, nil
	})
	if err != nil {
		return nil, err
	}

	metrics := result.([]sdkgraphrag.RemediationMetric)
	overallRate, overallMTTR := q.helper.calculateOverallMetrics(metrics)

	timeRange := sdkgraphrag.TimeRange{}
	if opts.TimeRange != nil {
		timeRange = *opts.TimeRange
	} else {
		timeRange = sdkgraphrag.TimeRange{Start: time.Now().AddDate(0, -3, 0), End: time.Now()}
	}

	dataLimitations := ""
	if len(metrics) == 0 {
		dataLimitations = "no remediation data found for the specified parameters"
	}
	return &sdkgraphrag.RemediationResult{
		Metrics:         metrics,
		OverallRate:     overallRate,
		OverallMTTR:     overallMTTR,
		TimeRange:       timeRange,
		DataLimitations: dataLimitations,
	}, nil
}

// sessionRisk is a session-backed RiskScoreCalculator.
type sessionRisk struct {
	session neo4j.SessionWithContext
	helper  RiskScoreCalculator
}

// Execute runs the risk score calculation on the shared session.
func (c *sessionRisk) Execute(ctx context.Context, opts sdkgraphrag.RiskScoreOpts) (*sdkgraphrag.RiskScoreResult, error) {
	if opts.Algorithm == "" {
		opts.Algorithm = "weighted_findings"
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	cypher, params := c.helper.buildQuery(opts)

	result, err := c.session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var assets []assetData
		for records.Next(ctx) {
			assets = append(assets, c.helper.parseAssetData(records.Record()))
		}
		if err := records.Err(); err != nil {
			return nil, err
		}
		return assets, nil
	})
	if err != nil {
		return nil, err
	}

	rawAssets := result.([]assetData)
	scoredAssets := make([]sdkgraphrag.AssetRiskScore, 0, len(rawAssets))
	for _, asset := range rawAssets {
		scoredAssets = append(scoredAssets, c.helper.calculateScore(asset, opts.Algorithm))
	}

	var portfolioScore float64
	var portfolioTier string
	if opts.AssetID == "all" || opts.AssetID == "" {
		portfolioScore, portfolioTier = c.helper.calculatePortfolioRisk(scoredAssets)
	}

	return &sdkgraphrag.RiskScoreResult{
		Assets:             scoredAssets,
		PortfolioRiskScore: portfolioScore,
		PortfolioRiskTier:  portfolioTier,
	}, nil
}

// sessionPatterns is a session-backed AttackPatternAnalyzer.
type sessionPatterns struct {
	session neo4j.SessionWithContext
	helper  AttackPatternAnalyzer
}

// Execute runs the attack pattern analysis on the shared session.
func (a *sessionPatterns) Execute(ctx context.Context, opts sdkgraphrag.PatternOpts) (*sdkgraphrag.PatternResult, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.MinSuccessRate <= 0 {
		opts.MinSuccessRate = 0.1
	}

	cypher, params := a.helper.buildQuery(opts)

	result, err := a.session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, params)
		if err != nil {
			return nil, err
		}
		var patterns []sdkgraphrag.IntelligenceAttackPattern
		for records.Next(ctx) {
			pattern := a.helper.parsePattern(records.Record())
			if pattern.SuccessRate >= opts.MinSuccessRate {
				patterns = append(patterns, pattern)
			}
		}
		if err := records.Err(); err != nil {
			return nil, err
		}
		return patterns, nil
	})
	if err != nil {
		return nil, err
	}

	patterns := result.([]sdkgraphrag.IntelligenceAttackPattern)
	return &sdkgraphrag.PatternResult{
		Patterns:      patterns,
		TotalPatterns: len(patterns),
	}, nil
}

// sessionSimilarity is a session-backed SimilarTargetFinder.
type sessionSimilarity struct {
	session neo4j.SessionWithContext
	helper  SimilarTargetFinder
}

// Execute runs the similar target discovery on the shared session.
// Unlike the driver-backed version, the session is pre-opened; we pass it
// directly to the helper methods (getTargetData / getCandidateTargets) which
// already accept neo4j.SessionWithContext.
func (f *sessionSimilarity) Execute(ctx context.Context, opts sdkgraphrag.SimilarTargetsOpts) (*sdkgraphrag.SimilarTargetsResult, error) {
	if opts.K <= 0 {
		opts.K = 10
	}
	if len(opts.Features) == 0 {
		opts.Features = []string{"technology_stack", "port_profile", "vuln_profile"}
	}

	refData, err := f.helper.getTargetData(ctx, f.session, opts.TargetID)
	if err != nil {
		return nil, err
	}

	candidates, err := f.helper.getCandidateTargets(ctx, f.session, opts.TargetID)
	if err != nil {
		return nil, err
	}

	similarTargets := make([]sdkgraphrag.SimilarTarget, 0, len(candidates))
	for _, candidate := range candidates {
		similarity := f.helper.calculateSimilarity(refData, candidate, opts.Features)
		if similarity.SimilarityScore > 0 {
			similarTargets = append(similarTargets, similarity)
		}
	}

	// sort descending by similarity score
	for i := 0; i < len(similarTargets); i++ {
		for j := i + 1; j < len(similarTargets); j++ {
			if similarTargets[j].SimilarityScore > similarTargets[i].SimilarityScore {
				similarTargets[i], similarTargets[j] = similarTargets[j], similarTargets[i]
			}
		}
	}
	if len(similarTargets) > opts.K {
		similarTargets = similarTargets[:opts.K]
	}

	return &sdkgraphrag.SimilarTargetsResult{
		ReferenceTargetID: opts.TargetID,
		SimilarTargets:    similarTargets,
		FeaturesUsed:      opts.Features,
	}, nil
}
