package intelligence

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
)

// RiskScoreCalculator calculates risk scores for assets.
type RiskScoreCalculator struct {
	driver neo4j.DriverWithContext
}

// NewRiskScoreCalculator creates a new risk score calculator.
func NewRiskScoreCalculator(driver neo4j.DriverWithContext) *RiskScoreCalculator {
	return &RiskScoreCalculator{
		driver: driver,
	}
}

// Execute runs the risk score calculation.
func (c *RiskScoreCalculator) Execute(ctx context.Context, opts sdkgraphrag.RiskScoreOpts) (*sdkgraphrag.RiskScoreResult, error) {
	// Apply defaults
	if opts.Algorithm == "" {
		opts.Algorithm = "weighted_findings"
	}
	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	// Fetch asset data
	session := c.driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		query, params := c.buildQuery(opts)
		records, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, fmt.Errorf("failed to execute risk score query: %w", err)
		}

		var assets []assetData
		for records.Next(ctx) {
			record := records.Record()
			asset := c.parseAssetData(record)
			assets = append(assets, asset)
		}

		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating results: %w", err)
		}

		return assets, nil
	})

	if err != nil {
		return nil, err
	}

	assets := result.([]assetData)

	// Calculate risk scores for each asset
	scoredAssets := make([]sdkgraphrag.AssetRiskScore, 0, len(assets))
	for _, asset := range assets {
		scored := c.calculateScore(asset, opts.Algorithm)
		scoredAssets = append(scoredAssets, scored)
	}

	// Calculate portfolio risk if querying all
	var portfolioScore float64
	var portfolioTier string
	if opts.AssetID == "all" || opts.AssetID == "" {
		portfolioScore, portfolioTier = c.calculatePortfolioRisk(scoredAssets)
	}

	return &sdkgraphrag.RiskScoreResult{
		Assets:             scoredAssets,
		PortfolioRiskScore: portfolioScore,
		PortfolioRiskTier:  portfolioTier,
	}, nil
}

// assetData holds raw data for risk calculation.
type assetData struct {
	assetID          string
	assetName        string
	criticalFindings int
	highFindings     int
	mediumFindings   int
	lowFindings      int
	infoFindings     int
	openFindings     int
	avgExposureDays  float64
	totalPorts       int
	totalServices    int
	totalEndpoints   int
	remediationRate  float64
	recurrenceCount  int
	avgCVSSScore     float64
	historicalScores []sdkgraphrag.HistoricalRiskScore
}

// buildQuery constructs the Cypher query for asset risk data.
func (c *RiskScoreCalculator) buildQuery(opts sdkgraphrag.RiskScoreOpts) (string, map[string]any) {
	params := map[string]any{
		"limit": opts.Limit,
	}

	whereClause := ""
	if opts.AssetID != "" && opts.AssetID != "all" {
		whereClause = "WHERE h.id = $asset_id"
		params["asset_id"] = opts.AssetID
	}

	query := fmt.Sprintf(`
		MATCH (h:Host)
		%s
		OPTIONAL MATCH (h)<-[:AFFECTS]-(f:Finding)
		OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
		OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:Service)
		OPTIONAL MATCH (s)-[:EXPOSES]->(e:Endpoint)
		WITH h,
			 count(DISTINCT f) AS total_findings,
			 sum(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings,
			 sum(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_findings,
			 sum(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium_findings,
			 sum(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low_findings,
			 sum(CASE WHEN f.severity IN ['info', 'informational'] THEN 1 ELSE 0 END) AS info_findings,
			 sum(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_findings,
			 avg(CASE WHEN f.status = 'open' AND f.created_at IS NOT NULL
			     THEN (timestamp() - f.created_at) / 86400000 ELSE 0 END) AS avg_exposure_days,
			 avg(COALESCE(f.cvss_score, 0)) AS avg_cvss_score,
			 sum(CASE WHEN f.status = 'recurred' THEN 1 ELSE 0 END) AS recurrence_count,
			 count(DISTINCT p) AS total_ports,
			 count(DISTINCT s) AS total_services,
			 count(DISTINCT e) AS total_endpoints
		RETURN h.id AS asset_id,
			   COALESCE(h.hostname, h.ip, h.id) AS asset_name,
			   critical_findings,
			   high_findings,
			   medium_findings,
			   low_findings,
			   info_findings,
			   open_findings,
			   avg_exposure_days,
			   avg_cvss_score,
			   recurrence_count,
			   total_ports,
			   total_services,
			   total_endpoints,
			   total_findings
		ORDER BY critical_findings DESC, high_findings DESC
		LIMIT $limit
	`, whereClause)

	return query, params
}

// parseAssetData converts a Neo4j record to assetData.
func (c *RiskScoreCalculator) parseAssetData(record *neo4j.Record) assetData {
	data := assetData{}

	if val, ok := record.Get("asset_id"); ok && val != nil {
		data.assetID = val.(string)
	}
	if val, ok := record.Get("asset_name"); ok && val != nil {
		data.assetName = val.(string)
	}
	if val, ok := record.Get("critical_findings"); ok && val != nil {
		data.criticalFindings = int(val.(int64))
	}
	if val, ok := record.Get("high_findings"); ok && val != nil {
		data.highFindings = int(val.(int64))
	}
	if val, ok := record.Get("medium_findings"); ok && val != nil {
		data.mediumFindings = int(val.(int64))
	}
	if val, ok := record.Get("low_findings"); ok && val != nil {
		data.lowFindings = int(val.(int64))
	}
	if val, ok := record.Get("info_findings"); ok && val != nil {
		data.infoFindings = int(val.(int64))
	}
	if val, ok := record.Get("open_findings"); ok && val != nil {
		data.openFindings = int(val.(int64))
	}
	if val, ok := record.Get("avg_exposure_days"); ok && val != nil {
		data.avgExposureDays = val.(float64)
	}
	if val, ok := record.Get("avg_cvss_score"); ok && val != nil {
		data.avgCVSSScore = val.(float64)
	}
	if val, ok := record.Get("recurrence_count"); ok && val != nil {
		data.recurrenceCount = int(val.(int64))
	}
	if val, ok := record.Get("total_ports"); ok && val != nil {
		data.totalPorts = int(val.(int64))
	}
	if val, ok := record.Get("total_services"); ok && val != nil {
		data.totalServices = int(val.(int64))
	}
	if val, ok := record.Get("total_endpoints"); ok && val != nil {
		data.totalEndpoints = int(val.(int64))
	}

	return data
}

// calculateScore calculates the risk score using the specified algorithm.
// After computing the base score it adjusts for attack-path depth by opening
// a read session and running a shortestPath Cypher query. When no path is
// found the score is unchanged. On any error the depth adjustment is skipped
// and a WARN is logged.
func (c *RiskScoreCalculator) calculateScore(data assetData, algorithm string) sdkgraphrag.AssetRiskScore {
	var score float64
	var factors []sdkgraphrag.RiskFactor

	switch algorithm {
	case "cvss_aggregate":
		score, factors = c.cvssAggregateScore(data)
	case "exposure_time":
		score, factors = c.exposureTimeScore(data)
	default: // weighted_findings
		score, factors = c.weightedFindingsScore(data)
	}

	// Ensure score is in 0-100 range
	score = math.Max(0, math.Min(100, score))

	// Attack-path depth adjustment.
	// Each hop toward an internet-facing endpoint increases risk by 10 %,
	// with the resulting score capped at 100.
	if data.assetID != "" && c.driver != nil {
		ctx := context.Background()
		depth := c.fetchAttackPathDepth(ctx, data.assetID)
		if depth > 0 {
			factor := 1.0 + 0.1*float64(depth)
			score = math.Min(100, score*factor)
		}
	}

	// Determine tier
	tier := c.scoreTier(score)

	// Generate recommendations
	recommendations := c.generateRecommendations(data, factors)

	return sdkgraphrag.AssetRiskScore{
		AssetID:          data.assetID,
		AssetName:        data.assetName,
		Score:            score,
		Tier:             tier,
		Factors:          factors,
		Recommendations:  recommendations,
		HistoricalScores: data.historicalScores,
	}
}

// weightedFindingsScore calculates risk based on weighted finding counts.
func (c *RiskScoreCalculator) weightedFindingsScore(data assetData) (float64, []sdkgraphrag.RiskFactor) {
	// Weights for different severities
	criticalWeight := 10.0
	highWeight := 5.0
	mediumWeight := 2.0
	lowWeight := 0.5
	infoWeight := 0.1

	// Calculate weighted score
	criticalContrib := float64(data.criticalFindings) * criticalWeight
	highContrib := float64(data.highFindings) * highWeight
	mediumContrib := float64(data.mediumFindings) * mediumWeight
	lowContrib := float64(data.lowFindings) * lowWeight
	infoContrib := float64(data.infoFindings) * infoWeight

	rawScore := criticalContrib + highContrib + mediumContrib + lowContrib + infoContrib

	// Normalize to 0-100 using logarithmic scale
	// This prevents scores from clustering at 100 for assets with many findings
	score := 0.0
	if rawScore > 0 {
		score = math.Log10(rawScore+1) * 25 // Logarithmic scaling
		score = math.Min(score, 100)
	}

	// Build factors
	factors := []sdkgraphrag.RiskFactor{
		{
			Name:        "critical_findings",
			Weight:      criticalContrib / (rawScore + 0.01),
			Value:       float64(data.criticalFindings),
			Description: fmt.Sprintf("%d critical findings (weight: %.1f each)", data.criticalFindings, criticalWeight),
		},
		{
			Name:        "high_findings",
			Weight:      highContrib / (rawScore + 0.01),
			Value:       float64(data.highFindings),
			Description: fmt.Sprintf("%d high findings (weight: %.1f each)", data.highFindings, highWeight),
		},
		{
			Name:        "medium_findings",
			Weight:      mediumContrib / (rawScore + 0.01),
			Value:       float64(data.mediumFindings),
			Description: fmt.Sprintf("%d medium findings (weight: %.1f each)", data.mediumFindings, mediumWeight),
		},
	}

	return score, factors
}

// cvssAggregateScore calculates risk based on CVSS scores.
func (c *RiskScoreCalculator) cvssAggregateScore(data assetData) (float64, []sdkgraphrag.RiskFactor) {
	// Use average CVSS score as base
	score := data.avgCVSSScore * 10 // Scale 0-10 to 0-100

	// Multiply by open findings factor
	openFactor := 1.0 + math.Log10(float64(data.openFindings)+1)*0.2

	score *= openFactor

	factors := []sdkgraphrag.RiskFactor{
		{
			Name:        "avg_cvss_score",
			Weight:      0.7,
			Value:       data.avgCVSSScore,
			Description: fmt.Sprintf("Average CVSS score: %.1f", data.avgCVSSScore),
		},
		{
			Name:        "open_findings",
			Weight:      0.3,
			Value:       float64(data.openFindings),
			Description: fmt.Sprintf("%d open findings", data.openFindings),
		},
	}

	return score, factors
}

// exposureTimeScore calculates risk based on how long findings remain open.
func (c *RiskScoreCalculator) exposureTimeScore(data assetData) (float64, []sdkgraphrag.RiskFactor) {
	// Base score from exposure time
	exposureScore := math.Min(data.avgExposureDays/30*25, 50) // Max 50 from exposure

	// Add severity component
	severityScore := float64(data.criticalFindings*10+data.highFindings*5+data.mediumFindings*2) / 10
	severityScore = math.Min(severityScore, 50) // Max 50 from severity

	score := exposureScore + severityScore

	factors := []sdkgraphrag.RiskFactor{
		{
			Name:        "avg_exposure_days",
			Weight:      exposureScore / (score + 0.01),
			Value:       data.avgExposureDays,
			Description: fmt.Sprintf("Average %.1f days of exposure", data.avgExposureDays),
		},
		{
			Name:        "severity_component",
			Weight:      severityScore / (score + 0.01),
			Value:       severityScore,
			Description: "Weighted severity contribution",
		},
	}

	return score, factors
}

// scoreTier converts a numeric score to a risk tier.
func (c *RiskScoreCalculator) scoreTier(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// generateRecommendations creates actionable recommendations based on risk factors.
func (c *RiskScoreCalculator) generateRecommendations(data assetData, factors []sdkgraphrag.RiskFactor) []string {
	var recommendations []string

	if data.criticalFindings > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Prioritize remediation of %d critical findings", data.criticalFindings))
	}

	if data.avgExposureDays > 30 {
		recommendations = append(recommendations,
			fmt.Sprintf("Reduce average exposure time from %.1f days", data.avgExposureDays))
	}

	if data.recurrenceCount > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("Investigate root cause of %d recurring vulnerabilities", data.recurrenceCount))
	}

	if data.totalEndpoints > 100 {
		recommendations = append(recommendations,
			"Consider reducing attack surface by consolidating endpoints")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Continue monitoring for new vulnerabilities")
	}

	return recommendations
}

// calculatePortfolioRisk calculates aggregate risk across all assets.
func (c *RiskScoreCalculator) calculatePortfolioRisk(assets []sdkgraphrag.AssetRiskScore) (float64, string) {
	if len(assets) == 0 {
		return 0, "low"
	}

	// Use weighted average with critical assets weighted more heavily
	var totalWeight, weightedSum float64
	for _, asset := range assets {
		weight := 1.0
		if asset.Tier == "critical" {
			weight = 4.0
		} else if asset.Tier == "high" {
			weight = 2.0
		}
		totalWeight += weight
		weightedSum += asset.Score * weight
	}

	score := weightedSum / totalWeight
	tier := c.scoreTier(score)

	return score, tier
}

// fetchHistoricalScores queries RiskSnapshot nodes linked to the asset and
// returns up to 90 records ordered newest-first.
//
// On any Neo4j error the error is logged and an empty slice is returned so
// that the caller can still produce a valid (though snapshot-less) result.
func (c *RiskScoreCalculator) fetchHistoricalScores(ctx context.Context, assetID string) []sdkgraphrag.HistoricalRiskScore {
	if c.driver == nil {
		return nil
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	const cypher = `MATCH (a {id: $asset_id})<-[:SNAPSHOT_OF]-(s:RiskSnapshot)
RETURN s.score AS score, s.tier AS tier, s.snapshotted_at AS snapshotted_at
ORDER BY s.snapshotted_at DESC LIMIT 90`

	raw, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, map[string]any{"asset_id": assetID})
		if err != nil {
			return nil, fmt.Errorf("failed to query historical scores: %w", err)
		}

		var scores []sdkgraphrag.HistoricalRiskScore
		for records.Next(ctx) {
			rec := records.Record()

			var score float64
			if v, ok := rec.Get("score"); ok && v != nil {
				score, _ = v.(float64)
			}

			var tier string
			if v, ok := rec.Get("tier"); ok && v != nil {
				tier, _ = v.(string)
			}

			var snapshotAt time.Time
			if v, ok := rec.Get("snapshotted_at"); ok && v != nil {
				switch t := v.(type) {
				case time.Time:
					snapshotAt = t
				case int64:
					snapshotAt = time.UnixMilli(t)
				}
			}

			scores = append(scores, sdkgraphrag.HistoricalRiskScore{
				Score: score,
				Tier:  tier,
				Date:  snapshotAt,
			})
		}
		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating historical score records: %w", err)
		}
		return scores, nil
	})
	if err != nil {
		slog.WarnContext(ctx, "failed to fetch historical risk scores",
			slog.String("asset_id", assetID),
			slog.String("error", err.Error()),
		)
		return nil
	}

	if raw == nil {
		return nil
	}
	return raw.([]sdkgraphrag.HistoricalRiskScore)
}

// fetchAttackPathDepth runs a shortestPath query from the asset to any
// internet-facing Endpoint via CONNECTS_TO|ROUTES_TO relationships and
// returns the path length. Returns 0 when no path exists or on error.
func (c *RiskScoreCalculator) fetchAttackPathDepth(ctx context.Context, assetID string) int {
	if c.driver == nil {
		return 0
	}

	session := c.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	const cypher = `MATCH p=shortestPath((a {id: $asset_id})-[:CONNECTS_TO|ROUTES_TO*1..8]->(e:Endpoint {internet_facing: true}))
RETURN length(p) AS depth`

	raw, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		records, err := tx.Run(ctx, cypher, map[string]any{"asset_id": assetID})
		if err != nil {
			return nil, fmt.Errorf("failed to query attack path: %w", err)
		}
		if records.Next(ctx) {
			rec := records.Record()
			if v, ok := rec.Get("depth"); ok && v != nil {
				if d, ok := v.(int64); ok {
					return int(d), nil
				}
			}
		}
		if err := records.Err(); err != nil {
			return nil, fmt.Errorf("error iterating attack path records: %w", err)
		}
		// No path found.
		return 0, nil
	})
	if err != nil {
		slog.WarnContext(ctx, "failed to fetch attack path depth",
			slog.String("asset_id", assetID),
			slog.String("error", err.Error()),
		)
		return 0
	}

	if raw == nil {
		return 0
	}
	return raw.(int)
}
