package finding

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// FindingAnalytics provides analytics and statistics for findings
type FindingAnalytics struct {
	store FindingStore
}

// FindingStats represents aggregated statistics for findings
type FindingStats struct {
	Total              int                           `json:"total"`
	BySeverity         map[agent.FindingSeverity]int `json:"by_severity"`
	ByCategory         map[FindingCategory]int       `json:"by_category"`
	ByStatus           map[FindingStatus]int         `json:"by_status"`
	AverageRiskScore   float64                       `json:"average_risk_score"`
	TopMitreTechniques []TechniqueCount              `json:"top_mitre_techniques"`
}

// TechniqueCount represents a MITRE technique with its occurrence count
type TechniqueCount struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
	Count         int    `json:"count"`
}

// TrendPoint represents a point in time-series data
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int       `json:"count"`
	RiskScore float64   `json:"risk_score"`
}

// VulnerabilityPattern represents a common vulnerability pattern
type VulnerabilityPattern struct {
	Category    FindingCategory `json:"category"`
	Subcategory string          `json:"subcategory"`
	Count       int             `json:"count"`
	AvgSeverity float64         `json:"avg_severity"`
}

// NewFindingAnalytics creates a new analytics instance
func NewFindingAnalytics(store FindingStore) *FindingAnalytics {
	return &FindingAnalytics{store: store}
}

// GetStatistics returns aggregated statistics for a mission's findings
func (a *FindingAnalytics) GetStatistics(ctx context.Context, missionID types.ID) (*FindingStats, error) {
	// Basic implementation using FindingStore interface
	findings, err := a.store.List(ctx, missionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}

	stats := &FindingStats{
		BySeverity:         make(map[agent.FindingSeverity]int),
		ByCategory:         make(map[FindingCategory]int),
		ByStatus:           make(map[FindingStatus]int),
		TopMitreTechniques: []TechniqueCount{},
	}

	// Track MITRE techniques
	techniqueMap := make(map[string]*TechniqueCount)

	var totalRisk float64
	for _, f := range findings {
		stats.Total++
		stats.BySeverity[f.Severity]++
		stats.ByCategory[FindingCategory(f.Category)]++
		stats.ByStatus[f.Status]++
		totalRisk += f.RiskScore

		// Aggregate MITRE ATT&CK techniques
		for _, tech := range f.GetMitreAttack() {
			if existing, ok := techniqueMap[tech.TechniqueID]; ok {
				existing.Count++
			} else {
				techniqueMap[tech.TechniqueID] = &TechniqueCount{
					TechniqueID:   tech.TechniqueID,
					TechniqueName: tech.TechniqueName,
					Count:         1,
				}
			}
		}

		// Aggregate MITRE ATLAS techniques
		for _, tech := range f.GetMitreAtlas() {
			if existing, ok := techniqueMap[tech.TechniqueID]; ok {
				existing.Count++
			} else {
				techniqueMap[tech.TechniqueID] = &TechniqueCount{
					TechniqueID:   tech.TechniqueID,
					TechniqueName: tech.TechniqueName,
					Count:         1,
				}
			}
		}
	}

	if stats.Total > 0 {
		stats.AverageRiskScore = totalRisk / float64(stats.Total)
	}

	// Convert technique map to sorted slice
	techniques := make([]TechniqueCount, 0, len(techniqueMap))
	for _, tc := range techniqueMap {
		techniques = append(techniques, *tc)
	}

	// Sort by count descending
	sort.Slice(techniques, func(i, j int) bool {
		return techniques[i].Count > techniques[j].Count
	})

	// Limit to top 10
	if len(techniques) > 10 {
		techniques = techniques[:10]
	}

	stats.TopMitreTechniques = techniques

	return stats, nil
}

// trendBucket represents a time bucket for aggregating findings
type trendBucket struct {
	timestamp time.Time
	count     int
	totalRisk float64
}

// determineBucketSize returns appropriate bucket size for the period
func determineBucketSize(period time.Duration) time.Duration {
	switch {
	case period <= 24*time.Hour:
		return time.Hour // Hourly buckets for day view
	case period <= 7*24*time.Hour:
		return 6 * time.Hour // 6-hour buckets for week view
	case period <= 30*24*time.Hour:
		return 24 * time.Hour // Daily buckets for month view
	default:
		return 7 * 24 * time.Hour // Weekly buckets for longer periods
	}
}

// GetTrends returns time-series data showing finding trends over a period
func (a *FindingAnalytics) GetTrends(ctx context.Context, missionID types.ID, period time.Duration) ([]TrendPoint, error) {
	// Get all findings for mission
	findings, err := a.store.List(ctx, missionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}

	if len(findings) == 0 {
		return []TrendPoint{}, nil
	}

	// Determine bucket size based on period
	bucketSize := determineBucketSize(period)

	// Group findings by time bucket
	buckets := make(map[time.Time]*trendBucket)

	for _, f := range findings {
		// Truncate to bucket
		bucketTime := f.CreatedAt.Truncate(bucketSize)

		if _, ok := buckets[bucketTime]; !ok {
			buckets[bucketTime] = &trendBucket{
				timestamp: bucketTime,
				count:     0,
				totalRisk: 0,
			}
		}

		buckets[bucketTime].count++
		buckets[bucketTime].totalRisk += f.RiskScore
	}

	// Convert to TrendPoints and calculate averages
	result := make([]TrendPoint, 0, len(buckets))
	for _, bucket := range buckets {
		avgRisk := 0.0
		if bucket.count > 0 {
			avgRisk = bucket.totalRisk / float64(bucket.count)
		}

		result = append(result, TrendPoint{
			Timestamp: bucket.timestamp,
			Count:     bucket.count,
			RiskScore: avgRisk,
		})
	}

	// Sort by timestamp ascending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})

	return result, nil
}

// GetRiskScore calculates a weighted aggregate risk score for a mission
// Uses severity-based weighting: critical=10, high=7, medium=4, low=1
func (a *FindingAnalytics) GetRiskScore(ctx context.Context, missionID types.ID) (float64, error) {
	findings, err := a.store.List(ctx, missionID, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to list findings: %w", err)
	}

	var totalScore float64
	var totalCount int

	for _, f := range findings {
		if f.Status != StatusResolved {
			weight := getSeverityWeight(f.Severity)
			totalScore += weight
			totalCount++
		}
	}

	if totalCount == 0 {
		return 0, nil
	}

	return totalScore / float64(totalCount), nil
}

// vulnAccumulator accumulates vulnerability pattern data
type vulnAccumulator struct {
	category    FindingCategory
	subcategory string
	count       int
	totalSev    float64
}

// AllFindingsLister is an optional interface for stores that support listing all findings
type AllFindingsLister interface {
	ScanAll(ctx context.Context) ([]EnhancedFinding, error)
}

// getAllFindings retrieves all findings across all missions
func (a *FindingAnalytics) getAllFindings(ctx context.Context) ([]EnhancedFinding, error) {
	// Try to use ScanAll if store supports it
	if lister, ok := a.store.(AllFindingsLister); ok {
		return lister.ScanAll(ctx)
	}

	// Fallback: return error if no method available
	return nil, fmt.Errorf("store does not support listing all findings")
}

// GetTopVulnerabilities returns the most common vulnerability patterns
func (a *FindingAnalytics) GetTopVulnerabilities(ctx context.Context, limit int) ([]VulnerabilityPattern, error) {
	// Get all findings - this could be optimized with Redis aggregation
	findings, err := a.getAllFindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	if len(findings) == 0 {
		return []VulnerabilityPattern{}, nil
	}

	// Aggregate by category + subcategory
	patterns := make(map[string]*vulnAccumulator)

	for _, f := range findings {
		key := fmt.Sprintf("%s:%s", f.Category, f.Subcategory)

		if _, ok := patterns[key]; !ok {
			patterns[key] = &vulnAccumulator{
				category:    FindingCategory(f.Category),
				subcategory: f.Subcategory,
				count:       0,
				totalSev:    0,
			}
		}

		patterns[key].count++
		patterns[key].totalSev += getSeverityWeight(f.Severity)
	}

	// Convert to VulnerabilityPattern slice
	result := make([]VulnerabilityPattern, 0, len(patterns))
	for _, acc := range patterns {
		avgSev := 0.0
		if acc.count > 0 {
			avgSev = acc.totalSev / float64(acc.count)
		}

		result = append(result, VulnerabilityPattern{
			Category:    acc.category,
			Subcategory: acc.subcategory,
			Count:       acc.count,
			AvgSeverity: avgSev,
		})
	}

	// Sort by count descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	// Apply limit
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

// GetRemediationProgress returns the count of open vs resolved findings
func (a *FindingAnalytics) GetRemediationProgress(ctx context.Context, missionID types.ID) (open, resolved int, err error) {
	findings, err := a.store.List(ctx, missionID, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list findings: %w", err)
	}

	for _, f := range findings {
		switch f.Status {
		case StatusResolved:
			resolved++
		case StatusOpen, StatusConfirmed:
			open++
		}
	}

	return open, resolved, nil
}

// getSeverityWeight returns the numeric weight for a severity level
// Used for both risk scoring and vulnerability pattern aggregation
func getSeverityWeight(severity agent.FindingSeverity) float64 {
	switch severity {
	case agent.SeverityCritical:
		return 4.0
	case agent.SeverityHigh:
		return 3.0
	case agent.SeverityMedium:
		return 2.0
	case agent.SeverityLow:
		return 1.0
	case agent.SeverityInfo:
		return 0.5
	default:
		return 0.0
	}
}
