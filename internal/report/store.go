package report

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Store manages report persistence and retrieval.
type Store interface {
	Save(ctx context.Context, report *Report, content []byte) error
	Get(ctx context.Context, id types.ID) (*Report, error)
	GetContent(ctx context.Context, id types.ID) ([]byte, error)
	List(ctx context.Context, filter ListFilter) ([]*Report, error)
	Delete(ctx context.Context, id types.ID) error
	GetByMission(ctx context.Context, missionID types.ID) ([]*Report, error)
}

// ListFilter configures report listing queries
type ListFilter struct {
	MissionID *types.ID
	Type      *ReportType
	Format    *ReportFormat
	FromDate  *time.Time
	ToDate    *time.Time
	Limit     int
	Offset    int
}
