package mission

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// MissionLoader provides unified loading of mission definitions from multiple sources:
// - Installed missions by name (from ~/.gibson/missions/)
// - File paths (absolute or relative)
// - Git URLs (temporary clone without installing)
type MissionLoader interface {
	// LoadByName loads a mission definition from ~/.gibson/missions/{name}/mission.yaml
	// Returns error if the mission is not installed or file cannot be read.
	LoadByName(ctx context.Context, name string) (*MissionDefinition, error)

	// LoadFromFile loads a mission definition from a file path.
	// Supports both absolute and relative paths.
	LoadFromFile(ctx context.Context, path string) (*MissionDefinition, error)

	// LoadFromURL loads a mission definition from a git repository URL.
	// The repository is cloned to a temporary directory, parsed, and returned
	// without persisting to ~/.gibson/missions/.
	// Supports branch/tag selection via URL fragment: https://github.com/org/repo#branch
	LoadFromURL(ctx context.Context, url string) (*MissionDefinition, error)

	// Load automatically detects the source type and routes to the appropriate loader:
	// - If source contains "://" or starts with "git@" → LoadFromURL
	// - If source is a file path that exists → LoadFromFile
	// - Otherwise → LoadByName (installed mission)
	Load(ctx context.Context, source string) (*MissionDefinition, error)
}

// DefaultMissionLoader implements MissionLoader with standard loading behavior.
type DefaultMissionLoader struct {
	// missionsDir is the directory where installed missions are stored.
	// Defaults to ~/.gibson/missions/
	missionsDir string

	// gitCloner handles git operations for LoadFromURL.
	// If nil, LoadFromURL will return an error.
	gitCloner GitCloner
}

// GitCloner abstracts git operations for testing and flexibility.
type GitCloner interface {
	// CloneToTemp clones a git repository to a temporary directory.
	// Returns the path to the temporary directory.
	// The caller is responsible for cleaning up the directory.
	CloneToTemp(ctx context.Context, url string, opts CloneOptions) (string, error)
}

// CloneOptions configures git clone operations.
type CloneOptions struct {
	// Branch specifies a branch to checkout after cloning.
	Branch string

	// Tag specifies a tag to checkout after cloning.
	Tag string

	// Depth specifies shallow clone depth (0 for full clone).
	Depth int
}

// NewMissionLoader creates a new mission loader with default settings.
// The missions directory defaults to ~/.gibson/missions/.
func NewMissionLoader() (*DefaultMissionLoader, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	missionsDir := filepath.Join(homeDir, ".gibson", "missions")

	return &DefaultMissionLoader{
		missionsDir: missionsDir,
	}, nil
}

// WithMissionsDir sets a custom missions directory (for testing).
func (l *DefaultMissionLoader) WithMissionsDir(dir string) *DefaultMissionLoader {
	l.missionsDir = dir
	return l
}

// WithGitCloner sets a custom git cloner implementation.
func (l *DefaultMissionLoader) WithGitCloner(cloner GitCloner) *DefaultMissionLoader {
	l.gitCloner = cloner
	return l
}

// LoadByName loads a mission definition from ~/.gibson/missions/{name}/mission.yaml
func (l *DefaultMissionLoader) LoadByName(ctx context.Context, name string) (*MissionDefinition, error) {
	if name == "" {
		return nil, fmt.Errorf("mission name cannot be empty")
	}

	// Sanitize mission name to prevent path traversal
	if strings.Contains(name, "..") || strings.Contains(name, string(filepath.Separator)) {
		return nil, fmt.Errorf("invalid mission name: %s", name)
	}

	missionDir := filepath.Join(l.missionsDir, name)

	// Check if mission directory exists
	if _, err := os.Stat(missionDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("mission '%s' is not installed (directory not found: %s)", name, missionDir)
	}

	// Try mission.yaml first (new format)
	missionPath := filepath.Join(missionDir, "mission.yaml")
	if _, err := os.Stat(missionPath); err == nil {
		def, err := ParseDefinition(missionPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission definition: %w", err)
		}
		return def, nil
	}

	// Fall back to mission.yaml (legacy format)
	missionDefinitionID := filepath.Join(missionDir, "mission.yaml")
	if _, err := os.Stat(missionDefinitionID); err == nil {
		def, err := ParseDefinition(missionDefinitionID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission definition: %w", err)
		}
		return def, nil
	}

	return nil, fmt.Errorf("mission '%s' has no mission.yaml or mission.yaml in %s", name, missionDir)
}

// LoadFromFile loads a mission definition from a file path.
func (l *DefaultMissionLoader) LoadFromFile(ctx context.Context, path string) (*MissionDefinition, error) {
	if path == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("mission file not found: %s", path)
	}

	// Parse the mission definition
	def, err := ParseDefinition(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mission definition from %s: %w", path, err)
	}

	return def, nil
}

// LoadFromURL loads a mission definition from a git repository URL.
// The repository is cloned to a temporary directory, the mission is parsed,
// and the definition is returned without persisting to ~/.gibson/missions/.
func (l *DefaultMissionLoader) LoadFromURL(ctx context.Context, url string) (*MissionDefinition, error) {
	if url == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	if l.gitCloner == nil {
		return nil, fmt.Errorf("git cloner not configured (cannot load from URL)")
	}

	// Parse URL to extract branch/tag from fragment
	opts := CloneOptions{
		Depth: 1, // Shallow clone for speed
	}

	// Split URL and fragment (e.g., https://github.com/org/repo#branch)
	parts := strings.SplitN(url, "#", 2)
	cleanURL := parts[0]
	if len(parts) == 2 {
		ref := parts[1]
		// Determine if it's a branch or tag (simple heuristic)
		if strings.HasPrefix(ref, "v") || strings.Contains(ref, ".") {
			opts.Tag = ref
		} else {
			opts.Branch = ref
		}
	}

	// Clone to temporary directory
	tempDir, err := l.gitCloner.CloneToTemp(ctx, cleanURL, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Clean up temp directory after we're done
	defer os.RemoveAll(tempDir)

	// Try to find mission.yaml or mission.yaml
	missionPath := filepath.Join(tempDir, "mission.yaml")
	if _, err := os.Stat(missionPath); err == nil {
		def, err := ParseDefinition(missionPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission.yaml: %w", err)
		}
		return def, nil
	}

	missionDefinitionID := filepath.Join(tempDir, "mission.yaml")
	if _, err := os.Stat(missionDefinitionID); err == nil {
		def, err := ParseDefinition(missionDefinitionID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission.yaml: %w", err)
		}
		return def, nil
	}

	return nil, fmt.Errorf("no mission.yaml or mission.yaml found in repository root")
}

// Load automatically detects the source type and routes to the appropriate loader.
func (l *DefaultMissionLoader) Load(ctx context.Context, source string) (*MissionDefinition, error) {
	if source == "" {
		return nil, fmt.Errorf("source cannot be empty")
	}

	// Detect source type
	sourceType := detectSourceType(source)

	switch sourceType {
	case SourceTypeURL:
		return l.LoadFromURL(ctx, source)
	case SourceTypeFile:
		return l.LoadFromFile(ctx, source)
	case SourceTypeName:
		return l.LoadByName(ctx, source)
	default:
		return nil, fmt.Errorf("could not determine source type for: %s", source)
	}
}

// SourceType represents the type of mission source.
type SourceType int

const (
	// SourceTypeUnknown indicates the source type could not be determined.
	SourceTypeUnknown SourceType = iota

	// SourceTypeURL indicates the source is a git repository URL.
	SourceTypeURL

	// SourceTypeFile indicates the source is a file path.
	SourceTypeFile

	// SourceTypeName indicates the source is an installed mission name.
	SourceTypeName
)

// detectSourceType determines the type of mission source based on its format.
func detectSourceType(source string) SourceType {
	// URL detection: contains "://" or starts with "git@"
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git@") {
		return SourceTypeURL
	}

	// File detection: check if file exists
	// Try absolute path first
	if filepath.IsAbs(source) {
		if _, err := os.Stat(source); err == nil {
			return SourceTypeFile
		}
		// Absolute path doesn't exist, could still be a mission name
		return SourceTypeName
	}

	// For relative paths, check if file exists
	if _, err := os.Stat(source); err == nil {
		return SourceTypeFile
	}

	// If it contains path separators but file doesn't exist, treat as file
	// (will fail later with better error message)
	if strings.Contains(source, string(filepath.Separator)) || strings.Contains(source, "/") {
		return SourceTypeFile
	}

	// Otherwise, treat as mission name
	return SourceTypeName
}

// Ensure DefaultMissionLoader implements MissionLoader at compile time.
var _ MissionLoader = (*DefaultMissionLoader)(nil)
