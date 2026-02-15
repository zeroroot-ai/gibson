package report

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DataAggregator collects data from all sources for report generation.
// Implementations coordinate multiple sub-aggregators to build a unified ReportData structure.
type DataAggregator interface {
	// Aggregate collects all data for a single mission.
	// Returns fully populated ReportData or error if critical sources fail.
	// Non-critical sources (GraphRAG, Timeline) may fail gracefully with partial data.
	Aggregate(ctx context.Context, missionID types.ID, opts AggregateOptions) (*ReportData, error)

	// AggregateMultiple collects data from multiple missions (for comparison reports).
	// Returns a slice of ReportData, one for each mission ID.
	AggregateMultiple(ctx context.Context, missionIDs []types.ID, opts AggregateOptions) ([]*ReportData, error)
}

// AggregateOptions configures what data to include and how to filter it.
type AggregateOptions struct {
	// Include flags control which data sources to query
	IncludeEvidence bool // Include evidence arrays for findings
	IncludeTimeline bool // Include event timeline
	IncludeGraphRAG bool // Include knowledge graph data (assets, relationships)
	IncludeMemory   bool // Include agent memory/context (future use)

	// Filtering options
	MinSeverity agent.FindingSeverity // Minimum severity level to include
	Categories  []string              // Only include specific finding categories
	DateFrom    *time.Time            // Filter events/findings from this date
	DateTo      *time.Time            // Filter events/findings to this date

	// Performance options
	Timeout      time.Duration // Maximum time for aggregation (0 = no timeout)
	MaxFindings  int           // Maximum number of findings to include (0 = unlimited)
	MaxEvents    int           // Maximum timeline events (0 = unlimited)
	ParallelMode bool          // Run sub-aggregators in parallel (default: true)
}

// DefaultAggregateOptions returns sensible defaults for report aggregation.
func DefaultAggregateOptions() AggregateOptions {
	return AggregateOptions{
		IncludeEvidence: true,
		IncludeTimeline: true,
		IncludeGraphRAG: true,
		IncludeMemory:   false,
		MinSeverity:     "",        // No filtering
		Categories:      nil,       // All categories
		DateFrom:        nil,       // No date filtering
		DateTo:          nil,       // No date filtering
		Timeout:         2 * time.Minute,
		MaxFindings:     0,         // Unlimited
		MaxEvents:       1000,      // Reasonable limit for timeline
		ParallelMode:    true,      // Parallel by default
	}
}

// WithMinSeverity sets the minimum severity filter.
func (o AggregateOptions) WithMinSeverity(severity agent.FindingSeverity) AggregateOptions {
	o.MinSeverity = severity
	return o
}

// WithCategories sets the category filter.
func (o AggregateOptions) WithCategories(categories ...string) AggregateOptions {
	o.Categories = categories
	return o
}

// WithDateRange sets the date range filter.
func (o AggregateOptions) WithDateRange(from, to time.Time) AggregateOptions {
	o.DateFrom = &from
	o.DateTo = &to
	return o
}

// WithTimeout sets the aggregation timeout.
func (o AggregateOptions) WithTimeout(timeout time.Duration) AggregateOptions {
	o.Timeout = timeout
	return o
}

// WithoutGraphRAG disables GraphRAG data collection.
func (o AggregateOptions) WithoutGraphRAG() AggregateOptions {
	o.IncludeGraphRAG = false
	return o
}

// WithoutTimeline disables timeline data collection.
func (o AggregateOptions) WithoutTimeline() AggregateOptions {
	o.IncludeTimeline = false
	return o
}
