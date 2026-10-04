// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	"context"

	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
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

// trendBucket represents a time bucket for aggregating findings
type trendBucket struct {
	timestamp time.Time
	count     int
	totalRisk float64
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
