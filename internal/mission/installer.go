package mission

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/component/git"
)

const (
	// DefaultInstallTimeout is the default timeout for mission installation operations
	DefaultInstallTimeout = 5 * time.Minute

	// MissionFileName is the name of the mission definition file
	MissionFileName = "mission.yaml"

	// MetadataFileName is the name of the installation metadata file
	MetadataFileName = ".gibson-meta.json"
)

// ComponentKind represents the type of component (agent, tool, plugin)
type ComponentKind string

const (
	// ComponentKindAgent represents an agent component
	ComponentKindAgent ComponentKind = "agent"
	// ComponentKindTool represents a tool component
	ComponentKindTool ComponentKind = "tool"
	// ComponentKindPlugin represents a plugin component
	ComponentKindPlugin ComponentKind = "plugin"
)

// Component represents a component's metadata
type Component struct {
	Name    string
	Kind    ComponentKind
	Version string
}

// ComponentStore defines the interface for querying installed components
type ComponentStore interface {
	// GetByName retrieves a component by kind and name
	GetByName(ctx context.Context, kind ComponentKind, name string) (*Component, error)
}

// ComponentInstallOptions contains options for component installation
type ComponentInstallOptions struct {
	Force   bool
	Yes     bool
	Timeout time.Duration
}

// ComponentInstallResult contains the result of a component installation
type ComponentInstallResult struct {
	Name       string
	Version    string
	DurationMs int64
}

// ComponentInstaller defines the interface for installing components
type ComponentInstaller interface {
	// Install installs a component from a URL or name
	Install(ctx context.Context, url string, kind ComponentKind, opts ComponentInstallOptions) (*ComponentInstallResult, error)
}

// InstallOptions contains options for installing a mission
type InstallOptions struct {
	// Branch specifies which branch to clone (optional)
	Branch string

	// Tag specifies which tag to clone (optional)
	Tag string

	// Force allows reinstalling even if mission exists
	Force bool

	// Timeout specifies the maximum time for the installation
	Timeout time.Duration

	// Yes auto-confirms dependency installation prompts
	Yes bool
}

// UninstallOptions contains options for uninstalling a mission
type UninstallOptions struct {
	// Force skips confirmation prompts
	Force bool
}

// UpdateOptions contains options for updating a mission
type UpdateOptions struct {
	// Timeout specifies the maximum time for the update
	Timeout time.Duration
}

// InstallResult contains the result of a mission installation operation
type InstallResult struct {
	// Name is the name of the installed mission
	Name string

	// Version is the version of the installed mission
	Version string

	// Path is the filesystem path where the mission was installed
	Path string

	// Dependencies contains information about installed dependencies
	Dependencies []InstalledDependency

	// Duration is how long the installation took
	Duration time.Duration
}

// InstalledDependency represents a dependency that was installed
type InstalledDependency struct {
	// Type is the dependency type (agent, tool, plugin)
	Type string

	// Name is the dependency name
	Name string

	// AlreadyInstalled indicates if it was already installed
	AlreadyInstalled bool
}

// UpdateResult contains the result of a mission update operation
type UpdateResult struct {
	// Name is the name of the updated mission
	Name string

	// Path is the filesystem path of the mission
	Path string

	// Duration is how long the update took
	Duration time.Duration

	// Updated indicates whether the mission was actually updated
	Updated bool

	// OldVersion is the version before the update
	OldVersion string

	// NewVersion is the version after the update
	NewVersion string
}

// installContext tracks resources created during installation for rollback on failure
type installContext struct {
	// missionDir is the mission directory created during installation
	missionDir string

	// dbRegistered indicates whether mission was registered in store
	dbRegistered bool

	// missionName is the name of the mission being installed
	missionName string
}

// rollback removes all resources created during installation
// Errors are intentionally ignored as this is cleanup code during error handling
func (ic *installContext) rollback(store MissionStore, ctx context.Context) {
	// Remove mission directory if it was created
	if ic.missionDir != "" {
		_ = os.RemoveAll(ic.missionDir)
	}

	// Remove database entry if it was registered
	// Note: MissionStore uses mission instance ID, not definition name
	// For now, skip DB cleanup as definitions will be stored separately (task 3.1)
}

// MissionInstaller defines the interface for installing, updating, and uninstalling missions
type MissionInstaller interface {
	// Install installs a mission from a git repository URL
	Install(ctx context.Context, url string, opts InstallOptions) (*InstallResult, error)

	// Uninstall removes an installed mission
	Uninstall(ctx context.Context, name string, opts UninstallOptions) error

	// Update updates an installed mission to the latest version
	Update(ctx context.Context, name string, opts UpdateOptions) (*UpdateResult, error)
}

// DefaultMissionInstaller implements MissionInstaller using git and MissionStore
type DefaultMissionInstaller struct {
	git                git.GitOperations
	store              MissionStore
	missionsDir        string
	componentStore     ComponentStore
	componentInstaller ComponentInstaller
}

// NewDefaultMissionInstaller creates a new DefaultMissionInstaller instance
func NewDefaultMissionInstaller(
	gitOps git.GitOperations,
	store MissionStore,
	missionsDir string,
	componentStore ComponentStore,
	componentInstaller ComponentInstaller,
) *DefaultMissionInstaller {
	return &DefaultMissionInstaller{
		git:                gitOps,
		store:              store,
		missionsDir:        missionsDir,
		componentStore:     componentStore,
		componentInstaller: componentInstaller,
	}
}

// Install installs a mission from a git repository URL
func (i *DefaultMissionInstaller) Install(ctx context.Context, url string, opts InstallOptions) (*InstallResult, error) {
	start := time.Now()
	result := &InstallResult{}

	// Set default timeout if not specified
	if opts.Timeout == 0 {
		opts.Timeout = DefaultInstallTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Step 1: Create temporary directory for cloning
	tempDir, err := os.MkdirTemp("", "gibson-mission-*")
	if err != nil {
		return result, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir) // Always clean up temp directory

	// Step 2: Clone repository to temp directory
	cloneOpts := git.CloneOptions{
		Branch: opts.Branch,
		Tag:    opts.Tag,
	}

	if err := i.git.Clone(url, tempDir, cloneOpts); err != nil {
		return result, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Step 3: Find and parse mission.yaml
	missionYAMLPath := filepath.Join(tempDir, MissionFileName)
	if _, err := os.Stat(missionYAMLPath); os.IsNotExist(err) {
		return result, fmt.Errorf("mission.yaml not found in repository")
	}

	definition, err := ParseDefinitionFromFile(missionYAMLPath)
	if err != nil {
		return result, fmt.Errorf("failed to parse mission.yaml: %w", err)
	}

	// Step 4: Validate the definition
	if err := ValidateDefinition(definition); err != nil {
		return result, fmt.Errorf("invalid mission definition: %w", err)
	}

	// Create install context for rollback on failure
	installCtx := &installContext{
		missionName: definition.Name,
	}

	// Step 5: Check if mission already exists (unless Force is set)
	missionDir := filepath.Join(i.missionsDir, definition.Name)
	if _, err := os.Stat(missionDir); err == nil && !opts.Force {
		return result, fmt.Errorf("mission '%s' already exists (use --force to overwrite)", definition.Name)
	}

	// If Force is set and mission exists, remove it first
	if opts.Force {
		if err := os.RemoveAll(missionDir); err != nil {
			return result, fmt.Errorf("failed to remove existing mission: %w", err)
		}
	}

	// Step 6: Create mission directory
	if err := os.MkdirAll(missionDir, 0755); err != nil {
		return result, fmt.Errorf("failed to create mission directory: %w", err)
	}
	installCtx.missionDir = missionDir

	// Step 7: Copy mission.yaml to mission directory
	destMissionYAML := filepath.Join(missionDir, MissionFileName)
	if err := copyFile(missionYAMLPath, destMissionYAML); err != nil {
		installCtx.rollback(i.store, ctx)
		return result, fmt.Errorf("failed to copy mission.yaml: %w", err)
	}

	// Step 8: Get git version (commit hash)
	version, err := i.git.GetVersion(tempDir)
	if err != nil {
		// Use manifest version as fallback
		version = definition.Version
	}

	// Step 9: Write .gibson-meta.json with installation metadata
	metadata := InstallMetadata{
		Name:        definition.Name,
		Version:     version,
		Source:      url,
		Branch:      opts.Branch,
		Tag:         opts.Tag,
		Commit:      version,
		InstalledAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	metadataPath := filepath.Join(missionDir, MetadataFileName)
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		installCtx.rollback(i.store, ctx)
		return result, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		installCtx.rollback(i.store, ctx)
		return result, fmt.Errorf("failed to write metadata: %w", err)
	}

	// Step 10: Check and install dependencies (task 4.3)
	if definition.Dependencies != nil && (i.componentStore != nil && i.componentInstaller != nil) {
		deps, err := i.checkAndInstallDependencies(ctx, definition, opts.Yes)
		if err != nil {
			installCtx.rollback(i.store, ctx)
			return result, fmt.Errorf("failed to install dependencies: %w", err)
		}
		result.Dependencies = deps
	}

	// Step 11: Store in database via MissionStore (will be implemented in task 3.1/3.2)
	// For now, we skip this step as the MissionStore interface needs to be extended
	// This will be implemented when CreateDefinition/GetDefinition methods are added

	// Build result
	result.Name = definition.Name
	result.Version = version
	result.Path = missionDir
	result.Duration = time.Since(start)

	return result, nil
}

// Uninstall removes an installed mission
func (i *DefaultMissionInstaller) Uninstall(ctx context.Context, name string, opts UninstallOptions) error {
	// Step 1: Check if mission exists
	missionDir := filepath.Join(i.missionsDir, name)
	if _, err := os.Stat(missionDir); os.IsNotExist(err) {
		return fmt.Errorf("mission '%s' not found", name)
	}

	// Step 2: Remove mission directory
	if err := os.RemoveAll(missionDir); err != nil {
		return fmt.Errorf("failed to remove mission directory: %w", err)
	}

	// Step 3: Delete from database (will be implemented in task 3.1/3.2)
	// For now, we skip this step as DeleteDefinition method needs to be added to MissionStore

	return nil
}

// Update updates an installed mission to the latest version
func (i *DefaultMissionInstaller) Update(ctx context.Context, name string, opts UpdateOptions) (*UpdateResult, error) {
	start := time.Now()
	result := &UpdateResult{
		Name: name,
	}

	// Set default timeout if not specified
	if opts.Timeout == 0 {
		opts.Timeout = DefaultInstallTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Step 1: Check if mission exists
	missionDir := filepath.Join(i.missionsDir, name)
	if _, err := os.Stat(missionDir); os.IsNotExist(err) {
		return result, fmt.Errorf("mission '%s' not found", name)
	}
	result.Path = missionDir

	// Step 2: Read existing metadata to get source URL
	metadataPath := filepath.Join(missionDir, MetadataFileName)
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return result, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata InstallMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return result, fmt.Errorf("failed to parse metadata: %w", err)
	}

	result.OldVersion = metadata.Version

	// Step 3: Clone repository to temp directory
	tempDir, err := os.MkdirTemp("", "gibson-mission-update-*")
	if err != nil {
		return result, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	cloneOpts := git.CloneOptions{
		Branch: metadata.Branch,
		Tag:    metadata.Tag,
	}

	if err := i.git.Clone(metadata.Source, tempDir, cloneOpts); err != nil {
		return result, fmt.Errorf("failed to clone repository: %w", err)
	}

	// Step 4: Get new version
	newVersion, err := i.git.GetVersion(tempDir)
	if err != nil {
		return result, fmt.Errorf("failed to get new version: %w", err)
	}
	result.NewVersion = newVersion

	// Step 5: Check if there were any changes
	if result.OldVersion == result.NewVersion {
		result.Duration = time.Since(start)
		result.Updated = false
		return result, nil
	}

	// Step 6: Parse and validate new mission.yaml
	missionYAMLPath := filepath.Join(tempDir, MissionFileName)
	if _, err := os.Stat(missionYAMLPath); os.IsNotExist(err) {
		return result, fmt.Errorf("mission.yaml not found in repository")
	}

	definition, err := ParseDefinitionFromFile(missionYAMLPath)
	if err != nil {
		return result, fmt.Errorf("failed to parse mission.yaml: %w", err)
	}

	if err := ValidateDefinition(definition); err != nil {
		return result, fmt.Errorf("invalid mission definition: %w", err)
	}

	// Step 7: Copy new mission.yaml
	destMissionYAML := filepath.Join(missionDir, MissionFileName)
	if err := copyFile(missionYAMLPath, destMissionYAML); err != nil {
		return result, fmt.Errorf("failed to copy mission.yaml: %w", err)
	}

	// Step 8: Check for new dependencies (task 4.5)
	if definition.Dependencies != nil && (i.componentStore != nil && i.componentInstaller != nil) {
		// Auto-confirm dependency installation during updates (don't prompt user)
		_, err := i.checkAndInstallDependencies(ctx, definition, true)
		if err != nil {
			return result, fmt.Errorf("failed to install new dependencies: %w", err)
		}
	}

	// Step 9: Update metadata
	metadata.Version = newVersion
	metadata.Commit = newVersion
	metadata.UpdatedAt = time.Now()

	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return result, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0644); err != nil {
		return result, fmt.Errorf("failed to write metadata: %w", err)
	}

	// Step 10: Update in database (will be implemented in task 3.1/3.2)
	// For now, we skip this step as UpdateDefinition method needs to be added to MissionStore

	result.Duration = time.Since(start)
	result.Updated = true

	return result, nil
}

// InstallMetadata contains installation metadata stored in .gibson-meta.json
type InstallMetadata struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Source      string    `json:"source"`
	Branch      string    `json:"branch,omitempty"`
	Tag         string    `json:"tag,omitempty"`
	Commit      string    `json:"commit"`
	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	// Get source file info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Open source file
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy contents
	if _, err := dstFile.ReadFrom(srcFile); err != nil {
		return err
	}

	// Set permissions
	return os.Chmod(dst, srcInfo.Mode())
}

// ParseDefinitionFromFile parses a mission definition from a YAML file.
// This delegates to ParseDefinition in parser.go.
func ParseDefinitionFromFile(path string) (*MissionDefinition, error) {
	return ParseDefinition(path)
}

// ValidateDefinition validates a mission definition.
// This delegates to Validate in validator.go.
func ValidateDefinition(def *MissionDefinition) error {
	errs := Validate(def)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// extractNameFromPath extracts a mission name from a file path.
// This is a helper for filesystem-based operations.
func extractNameFromPath(path string) string {
	// Get the directory name as a fallback name
	dir := filepath.Dir(path)
	name := filepath.Base(dir)
	if name == "." || name == "/" {
		name = "unknown-mission"
	}
	// Clean the name to be filesystem-safe
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ToLower(name)
	return name
}

// checkAndInstallDependencies checks for missing dependencies and installs them
func (i *DefaultMissionInstaller) checkAndInstallDependencies(ctx context.Context, definition *MissionDefinition, autoYes bool) ([]InstalledDependency, error) {
	var installedDeps []InstalledDependency

	// Check agent dependencies
	if definition.Dependencies.Agents != nil {
		for _, agentName := range definition.Dependencies.Agents {
			// Query ComponentStore to see if agent is already installed
			comp, err := i.componentStore.GetByName(ctx, ComponentKindAgent, agentName)
			if err == nil && comp != nil {
				// Agent already installed
				installedDeps = append(installedDeps, InstalledDependency{
					Type:             "agent",
					Name:             agentName,
					AlreadyInstalled: true,
				})
				continue
			}

			// Agent not installed - prompt user unless --yes flag is set
			if !autoYes {
				fmt.Printf("Mission requires agent '%s' which is not installed.\n", agentName)
				fmt.Printf("Install now? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					return installedDeps, fmt.Errorf("failed to read user input: %w", err)
				}
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					return installedDeps, fmt.Errorf("mission requires agent '%s' but installation was declined", agentName)
				}
			}

			// Install the agent
			fmt.Printf("Installing agent '%s'...\n", agentName)
			installOpts := ComponentInstallOptions{
				Force:   false,
				Yes:     true,
				Timeout: DefaultInstallTimeout,
			}

			// Assume agentName is a URL or registry path for now
			// In a real implementation, we'd resolve this from a registry
			_, err = i.componentInstaller.Install(ctx, agentName, ComponentKindAgent, installOpts)
			if err != nil {
				return installedDeps, fmt.Errorf("failed to install agent '%s': %w", agentName, err)
			}

			installedDeps = append(installedDeps, InstalledDependency{
				Type:             "agent",
				Name:             agentName,
				AlreadyInstalled: false,
			})
			fmt.Printf("Successfully installed agent '%s'\n", agentName)
		}
	}

	// Check tool dependencies
	if definition.Dependencies.Tools != nil {
		for _, toolName := range definition.Dependencies.Tools {
			// Query ComponentStore to see if tool is already installed
			comp, err := i.componentStore.GetByName(ctx, ComponentKindTool, toolName)
			if err == nil && comp != nil {
				// Tool already installed
				installedDeps = append(installedDeps, InstalledDependency{
					Type:             "tool",
					Name:             toolName,
					AlreadyInstalled: true,
				})
				continue
			}

			// Tool not installed - prompt user unless --yes flag is set
			if !autoYes {
				fmt.Printf("Mission requires tool '%s' which is not installed.\n", toolName)
				fmt.Printf("Install now? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					return installedDeps, fmt.Errorf("failed to read user input: %w", err)
				}
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					return installedDeps, fmt.Errorf("mission requires tool '%s' but installation was declined", toolName)
				}
			}

			// Install the tool
			fmt.Printf("Installing tool '%s'...\n", toolName)
			installOpts := ComponentInstallOptions{
				Force:   false,
				Yes:     true,
				Timeout: DefaultInstallTimeout,
			}

			// Assume toolName is a URL or registry path for now
			_, err = i.componentInstaller.Install(ctx, toolName, ComponentKindTool, installOpts)
			if err != nil {
				return installedDeps, fmt.Errorf("failed to install tool '%s': %w", toolName, err)
			}

			installedDeps = append(installedDeps, InstalledDependency{
				Type:             "tool",
				Name:             toolName,
				AlreadyInstalled: false,
			})
			fmt.Printf("Successfully installed tool '%s'\n", toolName)
		}
	}

	// Check plugin dependencies
	if definition.Dependencies.Plugins != nil {
		for _, pluginName := range definition.Dependencies.Plugins {
			// Query ComponentStore to see if plugin is already installed
			comp, err := i.componentStore.GetByName(ctx, ComponentKindPlugin, pluginName)
			if err == nil && comp != nil {
				// Plugin already installed
				installedDeps = append(installedDeps, InstalledDependency{
					Type:             "plugin",
					Name:             pluginName,
					AlreadyInstalled: true,
				})
				continue
			}

			// Plugin not installed - prompt user unless --yes flag is set
			if !autoYes {
				fmt.Printf("Mission requires plugin '%s' which is not installed.\n", pluginName)
				fmt.Printf("Install now? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				response, err := reader.ReadString('\n')
				if err != nil {
					return installedDeps, fmt.Errorf("failed to read user input: %w", err)
				}
				response = strings.TrimSpace(strings.ToLower(response))
				if response != "y" && response != "yes" {
					return installedDeps, fmt.Errorf("mission requires plugin '%s' but installation was declined", pluginName)
				}
			}

			// Install the plugin
			fmt.Printf("Installing plugin '%s'...\n", pluginName)
			installOpts := ComponentInstallOptions{
				Force:   false,
				Yes:     true,
				Timeout: DefaultInstallTimeout,
			}

			// Assume pluginName is a URL or registry path for now
			_, err = i.componentInstaller.Install(ctx, pluginName, ComponentKindPlugin, installOpts)
			if err != nil {
				return installedDeps, fmt.Errorf("failed to install plugin '%s': %w", pluginName, err)
			}

			installedDeps = append(installedDeps, InstalledDependency{
				Type:             "plugin",
				Name:             pluginName,
				AlreadyInstalled: false,
			})
			fmt.Printf("Successfully installed plugin '%s'\n", pluginName)
		}
	}

	return installedDeps, nil
}
