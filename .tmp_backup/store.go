package report

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Store manages report persistence and retrieval.
// Implementations handle both report metadata (in SQLite) and file content (on filesystem).
type Store interface {
	// Save stores a generated report with its content.
	// The report metadata is stored in the database, and the file content
	// is written to the filesystem at the path specified in report.FilePath.
	Save(ctx context.Context, report *Report, content []byte) error

	// Get retrieves a report by ID.
	// Returns the report metadata without the file content.
	Get(ctx context.Context, id types.ID) (*Report, error)

	// GetContent retrieves the report file content by ID.
	// This is separate from Get to allow retrieving metadata without loading large files.
	GetContent(ctx context.Context, id types.ID) ([]byte, error)

	// List lists reports with filtering and pagination.
	List(ctx context.Context, filter ListFilter) ([]*Report, error)

	// Delete removes a report and its file content.
	Delete(ctx context.Context, id types.ID) error

	// GetByMission gets all reports for a specific mission.
	GetByMission(ctx context.Context, missionID types.ID) ([]*Report, error)
}

// ListFilter configures report listing queries
type ListFilter struct {
	// Filtering
	MissionID *types.ID     // Filter by mission ID
	Type      *ReportType   // Filter by report type
	Format    *ReportFormat // Filter by report format
	FromDate  *time.Time    // Filter reports generated after this date
	ToDate    *time.Time    // Filter reports generated before this date

	// Pagination
	Limit  int // Maximum number of results (0 = unlimited)
	Offset int // Number of results to skip
}
