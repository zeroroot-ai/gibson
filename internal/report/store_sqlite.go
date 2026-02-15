package report

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

// SQLiteStore implements Store using SQLite for metadata and filesystem for content
type SQLiteStore struct {
	db      *database.DB
	baseDir string // Base directory for report storage (e.g., ~/.gibson/reports)
}

// NewSQLiteStore creates a new SQLite-backed report store
func NewSQLiteStore(db *database.DB, baseDir string) (*SQLiteStore, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, NewStorageError("create_base_dir", err).WithPath(baseDir)
	}

	return &SQLiteStore{
		db:      db,
		baseDir: baseDir,
	}, nil
}

// Save stores a generated report with its content
func (s *SQLiteStore) Save(ctx context.Context, report *Report, content []byte) error {
	// Calculate checksum
	hash := sha256.Sum256(content)
	report.Checksum = hex.EncodeToString(hash[:])
	report.FileSize = int64(len(content))

	// Create mission-specific directory
	missionDir := filepath.Join(s.baseDir, report.MissionID.String())
	if err := os.MkdirAll(missionDir, 0755); err != nil {
		return NewStorageError("create_mission_dir", err).WithPath(missionDir)
	}

	// Construct file path with format extension
	filename := fmt.Sprintf("%s.%s", report.ID.String(), strings.ToLower(report.Format.String()))
	filePath := filepath.Join(missionDir, filename)
	report.FilePath = filePath

	// Write content to file
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return NewStorageError("write_file", err).WithPath(filePath)
	}

	// Marshal JSON fields
	optionsJSON, err := json.Marshal(report.Options)
	if err != nil {
		return NewStorageError("marshal_options", err).WithReportID(report.ID)
	}

	metadataJSON, err := json.Marshal(report.Metadata)
	if err != nil {
		return NewStorageError("marshal_metadata", err).WithReportID(report.ID)
	}

	// Store metadata in database
	query := `
		INSERT INTO reports (
			id, mission_id, type, format, title, summary,
			generated_at, generated_by, template_used,
			options, metadata, file_path, file_size, checksum
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			summary = excluded.summary,
			options = excluded.options,
			metadata = excluded.metadata,
			file_path = excluded.file_path,
			file_size = excluded.file_size,
			checksum = excluded.checksum
	`

	_, err = s.db.ExecContext(ctx, query,
		report.ID.String(),
		report.MissionID.String(),
		report.Type.String(),
		report.Format.String(),
		report.Title,
		report.Summary,
		report.GeneratedAt,
		report.GeneratedBy,
		report.TemplateUsed,
		string(optionsJSON),
		string(metadataJSON),
		report.FilePath,
		report.FileSize,
		report.Checksum,
	)

	if err != nil {
		return NewStorageError("insert_report", err).WithReportID(report.ID)
	}

	return nil
}

// Get retrieves a report by ID (metadata only)
func (s *SQLiteStore) Get(ctx context.Context, id types.ID) (*Report, error) {
	query := `
		SELECT
			id, mission_id, type, format, title, summary,
			generated_at, generated_by, template_used,
			options, metadata, file_path, file_size, checksum
		FROM reports
		WHERE id = ?
	`

	row := s.db.QueryRowContext(ctx, query, id.String())
	report, err := s.scanReport(row)
	if err == sql.ErrNoRows {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, NewStorageError("get_report", err).WithReportID(id)
	}

	return report, nil
}

// GetContent retrieves the report file content
func (s *SQLiteStore) GetContent(ctx context.Context, id types.ID) ([]byte, error) {
	// First get the file path from database
	var filePath string
	query := "SELECT file_path FROM reports WHERE id = ?"
	err := s.db.QueryRowContext(ctx, query, id.String()).Scan(&filePath)
	if err == sql.ErrNoRows {
		return nil, ErrReportNotFound
	}
	if err != nil {
		return nil, NewStorageError("get_file_path", err).WithReportID(id)
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, NewStorageError("read_file", fmt.Errorf("report file not found")).
				WithPath(filePath).WithReportID(id)
		}
		return nil, NewStorageError("read_file", err).WithPath(filePath)
	}

	return content, nil
}

// List lists reports with filtering
func (s *SQLiteStore) List(ctx context.Context, filter ListFilter) ([]*Report, error) {
	query := `
		SELECT
			id, mission_id, type, format, title, summary,
			generated_at, generated_by, template_used,
			options, metadata, file_path, file_size, checksum
		FROM reports
		WHERE 1=1
	`
	args := []interface{}{}

	// Apply filters
	if filter.MissionID != nil {
		query += " AND mission_id = ?"
		args = append(args, filter.MissionID.String())
	}

	if filter.Type != nil {
		query += " AND type = ?"
		args = append(args, filter.Type.String())
	}

	if filter.Format != nil {
		query += " AND format = ?"
		args = append(args, filter.Format.String())
	}

	if filter.FromDate != nil {
		query += " AND generated_at >= ?"
		args = append(args, *filter.FromDate)
	}

	if filter.ToDate != nil {
		query += " AND generated_at <= ?"
		args = append(args, *filter.ToDate)
	}

	// Order by generated_at descending (most recent first)
	query += " ORDER BY generated_at DESC"

	// Apply pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, NewStorageError("list_reports", err)
	}
	defer rows.Close()

	reports := []*Report{}
	for rows.Next() {
		report, err := s.scanReport(rows)
		if err != nil {
			return nil, NewStorageError("scan_report", err)
		}
		reports = append(reports, report)
	}

	if err := rows.Err(); err != nil {
		return nil, NewStorageError("iterate_reports", err)
	}

	return reports, nil
}

// Delete removes a report and its content
func (s *SQLiteStore) Delete(ctx context.Context, id types.ID) error {
	// Get file path before deleting from database
	var filePath string
	query := "SELECT file_path FROM reports WHERE id = ?"
	err := s.db.QueryRowContext(ctx, query, id.String()).Scan(&filePath)
	if err == sql.ErrNoRows {
		return ErrReportNotFound
	}
	if err != nil {
		return NewStorageError("get_file_path", err).WithReportID(id)
	}

	// Delete from database
	deleteQuery := "DELETE FROM reports WHERE id = ?"
	result, err := s.db.ExecContext(ctx, deleteQuery, id.String())
	if err != nil {
		return NewStorageError("delete_report", err).WithReportID(id)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return NewStorageError("get_rows_affected", err).WithReportID(id)
	}

	if rowsAffected == 0 {
		return ErrReportNotFound
	}

	// Delete file from filesystem
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		// Log warning but don't fail the operation if file doesn't exist
		return NewStorageError("delete_file", err).WithPath(filePath)
	}

	return nil
}

// GetByMission gets all reports for a mission
func (s *SQLiteStore) GetByMission(ctx context.Context, missionID types.ID) ([]*Report, error) {
	filter := ListFilter{MissionID: &missionID}
	return s.List(ctx, filter)
}

// scanReport scans a database row into a Report struct
func (s *SQLiteStore) scanReport(scanner interface {
	Scan(dest ...interface{}) error
}) (*Report, error) {
	var (
		idStr, missionIDStr, typeStr, formatStr string
		title, summary, generatedBy             string
		templateUsed                            string
		optionsJSON, metadataJSON               string
		filePath                                string
		fileSize                                int64
		checksum                                string
		generatedAt                             time.Time
	)

	err := scanner.Scan(
		&idStr,
		&missionIDStr,
		&typeStr,
		&formatStr,
		&title,
		&summary,
		&generatedAt,
		&generatedBy,
		&templateUsed,
		&optionsJSON,
		&metadataJSON,
		&filePath,
		&fileSize,
		&checksum,
	)
	if err != nil {
		return nil, err
	}

	// Parse IDs
	id, err := types.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report ID: %w", err)
	}

	missionID, err := types.ParseID(missionIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mission ID: %w", err)
	}

	// Unmarshal JSON fields
	var options ReportOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return nil, fmt.Errorf("failed to unmarshal options: %w", err)
	}

	var metadata ReportMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	report := &Report{
		ID:           id,
		MissionID:    missionID,
		Type:         ReportType(typeStr),
		Format:       ReportFormat(formatStr),
		Title:        title,
		Summary:      summary,
		GeneratedAt:  generatedAt,
		GeneratedBy:  generatedBy,
		TemplateUsed: templateUsed,
		Options:      options,
		Metadata:     metadata,
		FilePath:     filePath,
		FileSize:     fileSize,
		Checksum:     checksum,
	}

	return report, nil
}

// Ensure SQLiteStore implements Store interface at compile time
var _ Store = (*SQLiteStore)(nil)
