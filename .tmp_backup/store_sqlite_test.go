package report

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestSQLiteStore(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	reportsDir := filepath.Join(tempDir, "reports")

	// Open database
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.InitSchema(); err != nil {
		t.Fatalf("Failed to initialize schema: %v", err)
	}

	// Create store
	store, err := NewSQLiteStore(db, reportsDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	ctx := context.Background()

	// Create test mission ID
	missionID := types.NewID()

	// Create test report
	report := &Report{
		ID:           types.NewID(),
		MissionID:    missionID,
		Type:         ReportTypeTechnical,
		Format:       FormatPDF,
		Title:        "Test Security Report",
		Summary:      "This is a test report",
		GeneratedAt:  time.Now(),
		GeneratedBy:  "test-user",
		TemplateUsed: "default",
		Options: ReportOptions{
			IncludeEvidence:  true,
			IncludeMetrics:   true,
			RedactSensitive:  false,
			Language:         "en",
			MinSeverity:      "low",
			Categories:       []string{"security"},
		},
		Metadata: ReportMetadata{
			FindingCount:  5,
			CriticalCount: 1,
			HighCount:     2,
			MediumCount:   1,
			LowCount:      1,
			InfoCount:     0,
		},
	}

	testContent := []byte("This is test report content")

	// Test Save
	t.Run("Save", func(t *testing.T) {
		err := store.Save(ctx, report, testContent)
		if err != nil {
			t.Fatalf("Failed to save report: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(report.FilePath); os.IsNotExist(err) {
			t.Errorf("Report file was not created: %s", report.FilePath)
		}

		// Verify checksum was set
		if report.Checksum == "" {
			t.Error("Checksum was not set")
		}

		// Verify file size was set
		if report.FileSize != int64(len(testContent)) {
			t.Errorf("File size mismatch: got %d, want %d", report.FileSize, len(testContent))
		}
	})

	// Test Get
	t.Run("Get", func(t *testing.T) {
		retrieved, err := store.Get(ctx, report.ID)
		if err != nil {
			t.Fatalf("Failed to get report: %v", err)
		}

		if retrieved.ID != report.ID {
			t.Errorf("ID mismatch: got %s, want %s", retrieved.ID, report.ID)
		}

		if retrieved.MissionID != report.MissionID {
			t.Errorf("MissionID mismatch: got %s, want %s", retrieved.MissionID, report.MissionID)
		}

		if retrieved.Type != report.Type {
			t.Errorf("Type mismatch: got %s, want %s", retrieved.Type, report.Type)
		}

		if retrieved.Format != report.Format {
			t.Errorf("Format mismatch: got %s, want %s", retrieved.Format, report.Format)
		}

		if retrieved.Title != report.Title {
			t.Errorf("Title mismatch: got %s, want %s", retrieved.Title, report.Title)
		}
	})

	// Test GetContent
	t.Run("GetContent", func(t *testing.T) {
		content, err := store.GetContent(ctx, report.ID)
		if err != nil {
			t.Fatalf("Failed to get content: %v", err)
		}

		if string(content) != string(testContent) {
			t.Errorf("Content mismatch: got %s, want %s", string(content), string(testContent))
		}
	})

	// Test GetByMission
	t.Run("GetByMission", func(t *testing.T) {
		reports, err := store.GetByMission(ctx, missionID)
		if err != nil {
			t.Fatalf("Failed to get reports by mission: %v", err)
		}

		if len(reports) != 1 {
			t.Errorf("Expected 1 report, got %d", len(reports))
		}

		if len(reports) > 0 && reports[0].ID != report.ID {
			t.Errorf("Report ID mismatch: got %s, want %s", reports[0].ID, report.ID)
		}
	})

	// Test List with filter
	t.Run("List", func(t *testing.T) {
		reportType := ReportTypeTechnical
		reportFormat := FormatPDF
		filter := ListFilter{
			MissionID: &missionID,
			Type:      &reportType,
			Format:    &reportFormat,
		}

		reports, err := store.List(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to list reports: %v", err)
		}

		if len(reports) != 1 {
			t.Errorf("Expected 1 report, got %d", len(reports))
		}
	})

	// Test Delete
	t.Run("Delete", func(t *testing.T) {
		err := store.Delete(ctx, report.ID)
		if err != nil {
			t.Fatalf("Failed to delete report: %v", err)
		}

		// Verify report is gone from database
		_, err = store.Get(ctx, report.ID)
		if err != ErrReportNotFound {
			t.Errorf("Expected ErrReportNotFound, got %v", err)
		}

		// Verify file is deleted
		if _, err := os.Stat(report.FilePath); !os.IsNotExist(err) {
			t.Error("Report file was not deleted")
		}
	})

	// Test error cases
	t.Run("GetNonExistent", func(t *testing.T) {
		_, err := store.Get(ctx, types.NewID())
		if err != ErrReportNotFound {
			t.Errorf("Expected ErrReportNotFound, got %v", err)
		}
	})

	t.Run("DeleteNonExistent", func(t *testing.T) {
		err := store.Delete(ctx, types.NewID())
		if err != ErrReportNotFound {
			t.Errorf("Expected ErrReportNotFound, got %v", err)
		}
	})
}
