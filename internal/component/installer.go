package component

import (
	"context"

	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sdkGraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/gibson/internal/component/build"
	"github.com/zeroroot-ai/gibson/internal/component/git"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// DefaultInstallTimeout is the default timeout for installation operations
	DefaultInstallTimeout = 5 * time.Minute

	// DefaultBuildTimeout is the default timeout for build operations
	DefaultBuildTimeout = 3 * time.Minute

	// ManifestFileName is the name of the component manifest file
	ManifestFileName = "component.yaml"
)

// InstallOptions contains options for installing a component
type InstallOptions struct {
	// Branch specifies which branch to clone (optional)
	Branch string

	// Tag specifies which tag to clone (optional)
	Tag string

	// Force allows reinstalling even if component exists
	Force bool

	// SkipBuild skips the build step
	SkipBuild bool

	// SkipRegister skips registration in the component registry
	SkipRegister bool

	// Timeout specifies the maximum time for the installation
	Timeout time.Duration

	// Subdir specifies a subdirectory within the repository where the component is located.
	// This is useful for mono-repos that contain multiple components.
	// Can also be specified in the repoURL using the fragment syntax: repo.git#path/to/component
	Subdir string

	// Verbose enables real-time streaming of build output to stdout/stderr
	Verbose bool
}

// ParsedRepoURL contains the parsed components of a repository URL
type ParsedRepoURL struct {
	// RepoURL is the base repository URL without the subdirectory fragment
	RepoURL string

	// Subdir is the subdirectory path extracted from the URL fragment (if any)
	Subdir string
}

// installContext tracks resources created during installation for rollback on failure
type installContext struct {
	// copiedArtifacts contains paths of artifacts copied to bin/
	copiedArtifacts []string

	// dbRegistered indicates whether component was registered in DB
	dbRegistered bool

	// componentKind is the kind of component being installed
	componentKind ComponentKind

	// componentName is the name of the component being installed
	componentName string
}

// rollback removes all resources created during installation
// Errors are intentionally ignored as this is cleanup code during error handling
func (ic *installContext) rollback(store ComponentStore, ctx context.Context) {
	// Remove all copied artifacts
	for _, artifactPath := range ic.copiedArtifacts {
		_ = os.Remove(artifactPath)
	}

	// Remove database entry if it was registered
	if ic.dbRegistered && store != nil {
		_ = store.Delete(ctx, ic.componentKind, ic.componentName)
	}
}

// ParseRepoURL parses a repository URL that may contain a subdirectory fragment.
// Supports the syntax: https://github.com/user/repo.git#path/to/component
// or: git@github.com:user/repo.git#path/to/component
func ParseRepoURL(fullURL string) ParsedRepoURL {
	result := ParsedRepoURL{RepoURL: fullURL}

	// Look for the fragment separator
	if idx := strings.LastIndex(fullURL, "#"); idx != -1 {
		result.RepoURL = fullURL[:idx]
		result.Subdir = fullURL[idx+1:]
	}

	return result
}

// UpdateOptions contains options for updating a component
type UpdateOptions struct {
	// Restart automatically restarts the component after update if it was running
	Restart bool

	// SkipBuild skips the build step
	SkipBuild bool

	// Timeout specifies the maximum time for the update
	Timeout time.Duration

	// Verbose enables real-time streaming of build output to stdout/stderr
	Verbose bool
}

// InstallResult contains the result of an installation operation
type InstallResult struct {
	// Component is the installed component
	Component *Component

	// Path is the filesystem path where the component was installed
	Path string

	// Duration is how long the installation took
	Duration time.Duration

	// BuildOutput contains output from the build step
	BuildOutput string

	// Installed indicates whether a new installation occurred
	Installed bool

	// Updated indicates whether an existing component was updated
	Updated bool
}

// UpdateResult contains the result of an update operation
type UpdateResult struct {
	// Component is the updated component
	Component *Component

	// Path is the filesystem path of the component
	Path string

	// Duration is how long the update took
	Duration time.Duration

	// BuildOutput contains output from the build step
	BuildOutput string

	// Updated indicates whether the component was actually updated
	Updated bool

	// Restarted indicates whether the component was restarted
	Restarted bool

	// OldVersion is the version before the update
	OldVersion string

	// NewVersion is the version after the update
	NewVersion string
}

// UninstallResult contains the result of an uninstall operation
type UninstallResult struct {
	// Name is the name of the uninstalled component
	Name string

	// Kind is the kind of the uninstalled component
	Kind ComponentKind

	// Path is the filesystem path that was removed
	Path string

	// Duration is how long the uninstall took
	Duration time.Duration

	// WasStopped indicates whether the component was stopped before removal
	WasStopped bool

	// WasRunning indicates whether the component was running before uninstall
	WasRunning bool
}

// InstallAllResult contains the result of installing all components from a mono-repo
type InstallAllResult struct {
	// RepoURL is the repository that was cloned
	RepoURL string

	// Successful contains results for components that installed successfully
	Successful []InstallResult

	// Failed contains information about components that failed to install
	Failed []InstallFailure

	// Skipped contains components that were skipped (already installed)
	Skipped []SkippedComponent

	// Duration is the total time for the operation
	Duration time.Duration

	// ComponentsFound is the total number of components discovered
	ComponentsFound int
}

// InstallFailure contains information about a failed installation
type InstallFailure struct {
	// Path is the subdirectory path where the component was found
	Path string

	// Name is the component name (if manifest was readable)
	Name string

	// Error is the error that occurred
	Error error
}

const (
	// SkipReasonAlreadyInstalled indicates a component was skipped because it's already installed
	SkipReasonAlreadyInstalled = "already installed"
)

// SkippedComponent contains information about a component that was skipped during installation
type SkippedComponent struct {
	// Path is the subdirectory path where the component was found
	Path string

	// Name is the component name
	Name string

	// Reason is the reason why the component was skipped
	Reason string
}

// Installer defines the interface for installing, updating, and uninstalling components
type Installer interface {
	// Install installs a component from a git repository URL
	Install(ctx context.Context, repoURL string, kind ComponentKind, opts InstallOptions) (*InstallResult, error)

	// InstallAll clones a mono-repo and installs all components of the specified kind found within it
	InstallAll(ctx context.Context, repoURL string, kind ComponentKind, opts InstallOptions) (*InstallAllResult, error)

	// Update updates an installed component to the latest version
	Update(ctx context.Context, kind ComponentKind, name string, opts UpdateOptions) (*UpdateResult, error)

	// UpdateAll updates all installed components of a specific kind
	UpdateAll(ctx context.Context, kind ComponentKind, opts UpdateOptions) ([]UpdateResult, error)

	// Uninstall removes an installed component
	Uninstall(ctx context.Context, kind ComponentKind, name string) (*UninstallResult, error)
}

// DefaultInstaller implements Installer using git, build executor, and ComponentStore
type DefaultInstaller struct {
	git              git.GitOperations
	builder          build.BuildExecutor
	store            ComponentStore
	lifecycle        LifecycleManager
	homeDir          string
	tracer           trace.Tracer
	taxonomyRegistry TaxonomyRegistry // Optional: unregisters agent taxonomy extensions on uninstall
}

// TaxonomyRegistry defines the interface for managing agent taxonomy extensions.
type TaxonomyRegistry interface {
	RegisterExtension(agentName string, ext *TaxonomyExtension) error
	UnregisterExtension(agentName string) error
}

// NewDefaultInstaller creates a new DefaultInstaller instance
func NewDefaultInstaller(gitOps git.GitOperations, builder build.BuildExecutor, store ComponentStore, lifecycle LifecycleManager) *DefaultInstaller {
	return &DefaultInstaller{
		git:       gitOps,
		builder:   builder,
		store:     store,
		lifecycle: lifecycle,
		homeDir:   getDefaultHomeDir(),
		tracer:    otel.GetTracerProvider().Tracer("gibson.component"),
	}
}

// getDefaultHomeDir returns the default Gibson home directory
func getDefaultHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".gibson")
}

// Install installs a component from a git repository URL
func (i *DefaultInstaller) Install(ctx context.Context, repoURL string, kind ComponentKind, opts InstallOptions) (*InstallResult, error) {
	// Start tracing span
	ctx, span := i.tracer.Start(ctx, SpanComponentInstall)
	defer span.End()

	start := time.Now()
	result := &InstallResult{}

	// Set default timeout if not specified
	if opts.Timeout == 0 {
		opts.Timeout = DefaultInstallTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Step 1: Validate component kind
	if !kind.IsValid() {
		err := NewInvalidKindError(kind.String())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(ErrorAttributes(err, "validate_kind")...)
		return result, err
	}

	// Parse the repository URL for subdirectory fragment (e.g., repo.git#path/to/component)
	parsed := ParseRepoURL(repoURL)
	actualRepoURL := parsed.RepoURL

	// Subdirectory can come from URL fragment or from options (options take precedence)
	subdir := parsed.Subdir
	if opts.Subdir != "" {
		subdir = opts.Subdir
	}

	// Add component metadata to span (we'll add component name after reading manifest)
	span.SetAttributes(
		attribute.String(AttrRepoURL, actualRepoURL),
		attribute.String(AttrComponentKind, kind.String()),
	)
	if subdir != "" {
		span.SetAttributes(attribute.String("gibson.component.subdir", subdir))
	}

	// Step 2: Clone to _repos directory (persistent, not temporary)
	// Extract repository name from URL
	repoName := extractRepoName(actualRepoURL)
	repoDir := filepath.Join(i.getReposDir(kind), repoName)

	// Check if repository already exists
	if _, err := os.Stat(repoDir); err == nil {
		if !opts.Force {
			// Repository exists, pull latest changes
			if err := i.git.Pull(repoDir); err != nil {
				span.AddEvent("git pull failed, using cached version", nil)
			}
		} else {
			// Force install: remove existing repository
			if err := os.RemoveAll(repoDir); err != nil {
				return result, WrapComponentError(ErrCodePermissionDenied, "failed to remove existing repository", err).
					WithContext("path", repoDir)
			}
		}
	}

	// Clone repository if it doesn't exist or was removed
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		// Ensure _repos directory exists
		if err := os.MkdirAll(i.getReposDir(kind), 0755); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "create_repos_dir")...)
			return result, WrapComponentError(ErrCodePermissionDenied, "failed to create _repos directory", err).
				WithContext("path", i.getReposDir(kind))
		}

		cloneOpts := git.CloneOptions{
			Branch: opts.Branch,
			Tag:    opts.Tag,
		}

		if err := i.git.Clone(actualRepoURL, repoDir, cloneOpts); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "clone_repository")...)
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to clone repository", err).
				WithContext("url", actualRepoURL)
		}
	}

	// Step 3: Determine the component directory (apply subdirectory if specified)
	componentSourceDir := repoDir
	if subdir != "" {
		componentSourceDir = filepath.Join(repoDir, subdir)
		// Verify the subdirectory exists
		if _, err := os.Stat(componentSourceDir); os.IsNotExist(err) {
			return result, WrapComponentError(ErrCodeManifestNotFound, "subdirectory not found in repository", err).
				WithContext("subdir", subdir).
				WithContext("url", actualRepoURL)
		}
	}

	// Step 4: Load manifest from the component source directory
	manifestPath := filepath.Join(componentSourceDir, ManifestFileName)
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return result, err // LoadManifest already returns proper ComponentError
	}

	// Add component name to span now that we have it
	span.SetAttributes(attribute.String(AttrComponentName, manifest.Name))

	// Create install context for rollback on failure
	installCtx := &installContext{
		componentKind: kind,
		componentName: manifest.Name,
	}

	// Step 5: Check if component already exists in database
	if !opts.Force && i.store != nil {
		if existing, err := i.store.GetByName(ctx, kind, manifest.Name); err == nil && existing != nil {
			// Check if this is an orphaned component (DB entry exists but binary is missing)
			if i.isOrphanedComponent(existing) {
				// Clean up the orphaned entry and proceed with installation
				if cleanupErr := i.cleanupOrphanedComponent(ctx, kind, manifest.Name, existing); cleanupErr != nil {
					return result, cleanupErr
				}
				// Cleanup succeeded - proceed with installation
			} else {
				// Valid existing component - fail with "already exists" error
				return result, NewComponentExistsError(manifest.Name).
					WithContext("path", existing.RepoPath)
			}
		}
	}

	// Step 6: Check dependencies
	if err := i.checkDependencies(ctx, manifest); err != nil {
		return result, err
	}

	// Step 7: Build component (unless SkipBuild is set)
	var buildOutput string
	var buildWorkDir string

	// Determine if we should build:
	// 1. If manifest.Build is specified, use that
	// 2. Otherwise, auto-detect if a Makefile exists with a build target
	shouldBuild := !opts.SkipBuild && (manifest.Build != nil || i.hasMakefileBuildTarget(componentSourceDir))

	if shouldBuild {
		// Determine build working directory
		buildWorkDir = componentSourceDir
		if manifest.Build != nil && manifest.Build.WorkDir != "" {
			buildWorkDir = filepath.Join(componentSourceDir, manifest.Build.WorkDir)
		}

		buildStart := time.Now()
		buildResult, err := i.buildComponent(ctx, componentSourceDir, manifest, opts.Verbose)
		buildDuration := time.Since(buildStart)

		if err != nil {
			// Cleanup on failure (remove repo if we just cloned it and force was set)
			if opts.Force {
				_ = os.RemoveAll(repoDir)
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "build_component")...)
			return result, err
		}
		buildOutput = buildResult.Stdout + "\n" + buildResult.Stderr

		// Add build metrics to span
		buildCommand := "make build"
		if manifest.Build != nil && manifest.Build.Command != "" {
			buildCommand = manifest.Build.Command
		}
		span.SetAttributes(
			attribute.String(AttrBuildCommand, buildCommand),
			attribute.Int64(AttrBuildDuration, buildDuration.Milliseconds()),
		)

		// Copy any artifacts from the repo's bin/ directory to the Gibson bin directory
		// This handles repos that build to a bin/ directory without explicit artifact lists
		if err := i.copyRepoBuildArtifacts(kind, componentSourceDir); err != nil {
			span.AddEvent("failed to copy repo build artifacts", trace.WithAttributes(
				attribute.String("error", err.Error()),
			))
			// Don't fail - the manifest might have explicit artifacts
		}
	} else {
		// If no build, use component source dir as work dir
		buildWorkDir = componentSourceDir
	}

	result.BuildOutput = buildOutput

	// Step 8: Copy artifacts to bin directory
	var binPath string
	if manifest.Build != nil && len(manifest.Build.Artifacts) > 0 {
		// Verify artifacts exist before attempting to copy them
		if err := i.verifyArtifactsExist(manifest.Build.Artifacts, buildWorkDir); err != nil {
			// Cleanup on failure
			if opts.Force {
				_ = os.RemoveAll(repoDir)
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "verify_artifacts")...)
			return result, err
		}

		// Copy artifacts from build work directory to bin/
		primaryArtifact, err := i.copyArtifactsToBin(kind, manifest.Build.Artifacts, buildWorkDir)
		if err != nil {
			// Cleanup on failure
			if opts.Force {
				_ = os.RemoveAll(repoDir)
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "copy_artifacts")...)
			return result, err
		}
		binPath = primaryArtifact
		// Track copied artifact for rollback on failure
		installCtx.copiedArtifacts = append(installCtx.copiedArtifacts, binPath)
	} else {
		// No artifacts specified in manifest - try to auto-detect binary
		// Look for an executable with the component name in the build directory
		detectedBinary := i.detectComponentBinary(manifest.Name, buildWorkDir)
		if detectedBinary != "" {
			// Copy the detected binary to bin/
			primaryArtifact, err := i.copyArtifactsToBin(kind, []string{detectedBinary}, buildWorkDir)
			if err != nil {
				// Log but don't fail - component might be script-based
				span.AddEvent("failed to copy auto-detected binary", trace.WithAttributes(
					attribute.String("binary", detectedBinary),
					attribute.String("error", err.Error()),
				))
				binPath = ""
			} else {
				binPath = primaryArtifact
				installCtx.copiedArtifacts = append(installCtx.copiedArtifacts, binPath)
				span.AddEvent("auto-detected and copied binary", trace.WithAttributes(
					attribute.String("binary", detectedBinary),
					attribute.String("bin_path", binPath),
				))
			}
		} else {
			// No binary detected - this might be a script-based component
			binPath = ""
		}
	}

	// Get the git version (commit hash)
	version, err := i.git.GetVersion(repoDir)
	if err != nil {
		// Use manifest version as fallback
		version = manifest.Version
	}

	// Step 9: Create component instance with RepoPath and BinPath
	component := &Component{
		Kind:      kind,
		Name:      manifest.Name,
		Version:   version,
		RepoPath:  componentSourceDir, // Path to source in _repos/
		BinPath:   binPath,            // Path to binary in bin/
		Source:    ComponentSourceExternal,
		Status:    ComponentStatusAvailable,
		Manifest:  manifest,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Validate component
	if err := component.Validate(); err != nil {
		// Rollback on validation failure
		installCtx.rollback(i.store, ctx)
		if opts.Force {
			_ = os.RemoveAll(repoDir)
		}
		return result, NewValidationFailedError("component validation failed", err)
	}

	// Step 10: Register component in database (unless SkipRegister is set)
	if !opts.SkipRegister && i.store != nil {
		if err := i.store.Create(ctx, component); err != nil {
			// Rollback on DB registration failure
			installCtx.rollback(i.store, ctx)
			if opts.Force {
				_ = os.RemoveAll(repoDir)
			}
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "register_component")...)
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to register component", err).
				WithComponent(manifest.Name)
		}
	}

	result.Component = component
	result.Duration = time.Since(start)
	result.Installed = true

	// Record successful installation
	span.SetStatus(codes.Ok, "component installed successfully")
	span.SetAttributes(ComponentAttributes(component)...)
	span.SetAttributes(InstallResultAttributes(result)...)

	return result, nil
}

// InstallAll clones a mono-repo and installs all components of the specified kind found within it.
// Uses persistent clones in _repos directory to avoid redundant cloning.
func (i *DefaultInstaller) InstallAll(ctx context.Context, repoURL string, kind ComponentKind, opts InstallOptions) (*InstallAllResult, error) {
	ctx, span := i.tracer.Start(ctx, "component.install_all")
	defer span.End()

	result := &InstallAllResult{
		RepoURL:    repoURL,
		Successful: make([]InstallResult, 0),
		Failed:     make([]InstallFailure, 0),
	}

	// 1. Extract repo name using extractRepoName(repoURL)
	repoName := extractRepoName(repoURL)

	// 2. Determine persistent path: filepath.Join(i.homeDir, kind.String()+"s", "_repos", repoName)
	repoDir := filepath.Join(i.homeDir, kind.String()+"s", "_repos", repoName)

	// 3. Clone to persistent path (create parent dir, clone or update if exists && Force)
	if err := os.MkdirAll(filepath.Dir(repoDir), 0755); err != nil {
		return result, err
	}

	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		cloneOpts := git.CloneOptions{Branch: opts.Branch, Tag: opts.Tag}
		if err := i.git.Clone(repoURL, repoDir, cloneOpts); err != nil {
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to clone repository", err)
		}
	} else if opts.Force {
		os.RemoveAll(repoDir)
		cloneOpts := git.CloneOptions{Branch: opts.Branch, Tag: opts.Tag}
		if err := i.git.Clone(repoURL, repoDir, cloneOpts); err != nil {
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to clone repository", err)
		}
	} else {
		// Repository exists and not forcing - check for updates
		if err := i.git.Pull(repoDir); err != nil {
			// Log warning but continue - the cached version might still work
			// This handles cases like network issues or detached HEAD state
			span.AddEvent("git pull failed, using cached version", nil)
		}
	}

	// 4. Load top-level manifest - ERROR if not found
	manifestPath := filepath.Join(repoDir, ManifestFileName)
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return result, fmt.Errorf("repository must have top-level component.yaml: %w", err)
	}

	// 5. Parse manifest.Kind and route
	manifestKind := ComponentKind(manifest.Kind)

	switch {
	case manifestKind.IsRepositoryKind():
		return i.installRepository(ctx, repoDir, manifest, kind, opts)
	case manifestKind.IsComponentKind():
		return i.installSingleComponent(ctx, repoDir, manifest, kind, opts)
	default:
		return result, fmt.Errorf("invalid manifest kind: %s (expected repository, tool, agent, or plugin)", manifest.Kind)
	}
}

// findComponentManifests recursively walks a directory and returns paths to all component.yaml files
func (i *DefaultInstaller) findComponentManifests(rootDir string) ([]string, error) {
	var manifests []string

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip directories we can't read
		}

		// Skip hidden directories (like .git)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}

		// Skip common non-component directories
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "vendor", "__pycache__", ".venv", "venv", "pkg", "build", "dist", "target":
				return filepath.SkipDir
			}
		}

		// Check if this is a component manifest
		if !d.IsDir() && (d.Name() == "component.yaml" || d.Name() == "component.json") {
			manifests = append(manifests, path)
		}

		return nil
	})

	return manifests, err
}

// installRepository installs all components from a repository manifest.
// It builds the repository once (if needed) and then registers all discovered/listed components.
func (i *DefaultInstaller) installRepository(ctx context.Context, repoDir string, manifest *Manifest, kind ComponentKind, opts InstallOptions) (*InstallAllResult, error) {
	// Start tracing span
	ctx, span := i.tracer.Start(ctx, "component.install_repository")
	defer span.End()

	start := time.Now()
	result := &InstallAllResult{
		RepoURL:    repoDir,
		Successful: make([]InstallResult, 0),
		Failed:     make([]InstallFailure, 0),
	}

	span.SetAttributes(
		attribute.String("gibson.repository.path", repoDir),
		attribute.String(AttrComponentKind, kind.String()),
	)

	// Step 1: Run repository-level build if manifest has build config and build is not skipped
	var buildOutput string
	if !opts.SkipBuild && manifest.Build != nil {
		buildStart := time.Now()
		buildResult, err := i.buildAtPath(ctx, repoDir, manifest.Build, opts.Verbose)
		buildDuration := time.Since(buildStart)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "build_repository")...)
			result.Duration = time.Since(start)
			return result, err
		}
		buildOutput = buildResult.Stdout + "\n" + buildResult.Stderr

		// Add build metrics to span
		span.SetAttributes(
			attribute.String(AttrBuildCommand, manifest.Build.Command),
			attribute.Int64(AttrBuildDuration, buildDuration.Milliseconds()),
		)

		// Step 1.5: Copy repository-level build artifacts to bin/ directory
		// Many repositories (like oss-tools) build all artifacts to a repo-level bin/ directory
		// We need to copy these to ~/.gibson/{kind}s/bin/ so they're discoverable
		if err := i.copyRepoBuildArtifacts(kind, repoDir); err != nil {
			span.AddEvent("failed to copy repo build artifacts", trace.WithAttributes(
				attribute.String("error", err.Error()),
			))
			// Don't fail - individual components may still have their own builds
		}
	}

	// Step 2: Find component paths
	var componentPaths []string
	var err error

	if len(manifest.Contents) > 0 {
		// Use explicit content list, filtering by kind
		for _, entry := range manifest.Contents {
			// Filter by kind if specified (empty kind means accept all)
			if entry.Kind != "" && entry.Kind != kind.String() {
				continue
			}

			// Build full path to component manifest
			componentManifestPath := filepath.Join(repoDir, entry.Path, ManifestFileName)

			// Verify the manifest exists
			if _, err := os.Stat(componentManifestPath); err == nil {
				componentPaths = append(componentPaths, componentManifestPath)
			} else {
				// Record as failure if manifest doesn't exist
				result.Failed = append(result.Failed, InstallFailure{
					Path: entry.Path,
					Error: WrapComponentError(ErrCodeManifestNotFound, "component manifest not found", err).
						WithContext("path", entry.Path),
				})
			}
		}
	} else if manifest.Discover {
		// Auto-discover components in the repository
		componentPaths, err = i.findComponentManifests(repoDir)
		if err != nil {
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to discover components", err)
		}
	}

	result.ComponentsFound = len(componentPaths)
	span.SetAttributes(attribute.Int("gibson.components_found", len(componentPaths)))

	if len(componentPaths) == 0 {
		result.Duration = time.Since(start)
		return result, nil
	}

	// Step 3: Process each component
	for _, manifestPath := range componentPaths {
		// Create install context for rollback on failure
		installCtx := &installContext{componentKind: kind}

		// Load component manifest
		compManifest, err := LoadManifest(manifestPath)
		if err != nil {
			// Get relative path for error reporting
			relPath, _ := filepath.Rel(repoDir, filepath.Dir(manifestPath))
			result.Failed = append(result.Failed, InstallFailure{
				Path:  relPath,
				Error: err,
			})
			continue
		}

		// Set component name in install context for rollback tracking
		installCtx.componentName = compManifest.Name

		// Get component directory (where the component manifest is located)
		componentDir := filepath.Dir(manifestPath)

		// Get relative path for error reporting
		relPath, err := filepath.Rel(repoDir, componentDir)
		if err != nil {
			relPath = componentDir
		}

		// Declare buildWorkDir - will be set based on whether build runs
		var buildWorkDir string

		// Check if component already exists in database
		if !opts.Force && i.store != nil {
			if existing, err := i.store.GetByName(ctx, kind, compManifest.Name); err == nil && existing != nil {
				// Check if this is an orphaned component (DB entry exists but binary is missing)
				if i.isOrphanedComponent(existing) {
					// Clean up the orphaned entry and proceed with installation
					if cleanupErr := i.cleanupOrphanedComponent(ctx, kind, compManifest.Name, existing); cleanupErr != nil {
						// Cleanup failed - add to Failed and continue
						result.Failed = append(result.Failed, InstallFailure{
							Path:  relPath,
							Name:  compManifest.Name,
							Error: cleanupErr,
						})
						continue
					}
					// Cleanup succeeded - proceed with installation (don't add to Failed, don't continue)
				} else {
					// Valid existing component - skip it
					result.Skipped = append(result.Skipped, SkippedComponent{
						Path:   relPath,
						Name:   compManifest.Name,
						Reason: SkipReasonAlreadyInstalled,
					})
					continue
				}
			}
		}

		// If Force is set and component exists, delete it first
		if opts.Force && i.store != nil {
			_ = i.store.Delete(ctx, kind, compManifest.Name)
		}

		// Build component if it has its own build config (component-level build)
		// Note: Repository-level build has already run in Step 1
		var componentBuildOutput string
		if !opts.SkipBuild && compManifest.Build != nil {
			buildStart := time.Now()
			buildResult, err := i.buildAtPath(ctx, componentDir, compManifest.Build, opts.Verbose)
			buildDuration := time.Since(buildStart)

			if err != nil {
				result.Failed = append(result.Failed, InstallFailure{
					Path:  relPath,
					Name:  compManifest.Name,
					Error: err,
				})
				continue
			}
			componentBuildOutput = buildResult.Stdout + "\n" + buildResult.Stderr

			span.SetAttributes(
				attribute.String(AttrBuildCommand+" component", compManifest.Build.Command),
				attribute.Int64(AttrBuildDuration+" component", buildDuration.Milliseconds()),
			)

			// Set buildWorkDir based on where the build actually ran
			buildWorkDir = componentDir
			if compManifest.Build.WorkDir != "" {
				buildWorkDir = filepath.Join(componentDir, compManifest.Build.WorkDir)
			}
		} else {
			// No build ran, artifacts should be in componentDir
			buildWorkDir = componentDir
		}

		// Verify artifacts exist before attempting to copy them
		if compManifest.Build != nil && len(compManifest.Build.Artifacts) > 0 {
			if err := i.verifyArtifactsExist(compManifest.Build.Artifacts, buildWorkDir); err != nil {
				result.Failed = append(result.Failed, InstallFailure{
					Path:  relPath,
					Name:  compManifest.Name,
					Error: err,
				})
				continue
			}
		}

		// Copy artifacts to bin/ directory
		var binPath string
		if compManifest.Build != nil && len(compManifest.Build.Artifacts) > 0 {
			binPath, err = i.copyArtifactsToBin(kind, compManifest.Build.Artifacts, buildWorkDir)
			if err != nil {
				// Rollback any resources created during this installation
				installCtx.rollback(i.store, ctx)
				result.Failed = append(result.Failed, InstallFailure{
					Path:  relPath,
					Name:  compManifest.Name,
					Error: err,
				})
				continue
			}
			// Track the copied artifact for rollback on subsequent failures
			installCtx.copiedArtifacts = append(installCtx.copiedArtifacts, binPath)
		} else {
			// No artifacts specified - this might be OK for some components
			// Use empty binPath (component might be library, script, etc.)
			binPath = ""
		}

		// Get the git version (commit hash) from the repository
		version, err := i.git.GetVersion(repoDir)
		if err != nil {
			// Use manifest version as fallback
			version = compManifest.Version
		}

		// Create component instance with new directory structure
		// RepoPath points to the component's subdirectory in _repos/
		// BinPath points to the artifact in bin/
		component := &Component{
			Kind:      kind,
			Name:      compManifest.Name,
			Version:   version,
			RepoPath:  componentDir, // Path to component in _repos/{repo-name}/{component-subdir}
			BinPath:   binPath,      // Path to binary in bin/{artifact-name}
			Source:    ComponentSourceExternal,
			Status:    ComponentStatusAvailable,
			Manifest:  compManifest,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Validate component
		if err := component.Validate(); err != nil {
			// Rollback any resources created during this installation
			installCtx.rollback(i.store, ctx)
			result.Failed = append(result.Failed, InstallFailure{
				Path:  relPath,
				Name:  compManifest.Name,
				Error: NewValidationFailedError("component validation failed", err),
			})
			continue
		}

		// Register component in database (unless SkipRegister is set)
		if !opts.SkipRegister && i.store != nil {
			if err := i.store.Create(ctx, component); err != nil {
				// Rollback any resources created during this installation
				installCtx.rollback(i.store, ctx)
				result.Failed = append(result.Failed, InstallFailure{
					Path: relPath,
					Name: compManifest.Name,
					Error: WrapComponentError(ErrCodeLoadFailed, "failed to register component", err).
						WithComponent(compManifest.Name),
				})
				continue
			}
		}

		// Record success
		// Merge repository build output with component-specific build output
		finalBuildOutput := buildOutput
		if componentBuildOutput != "" {
			finalBuildOutput = buildOutput + "\n--- Component Build ---\n" + componentBuildOutput
		}

		installResult := InstallResult{
			Component:   component,
			Path:        componentDir, // Path to component source in _repos/
			Duration:    0,            // Individual component installation is part of the overall repository installation
			BuildOutput: finalBuildOutput,
			Installed:   true,
		}
		result.Successful = append(result.Successful, installResult)
	}

	result.Duration = time.Since(start)

	// Set span status based on results
	if len(result.Failed) == 0 {
		span.SetStatus(codes.Ok, fmt.Sprintf("installed %d components successfully", len(result.Successful)))
	} else if len(result.Successful) > 0 {
		span.SetStatus(codes.Ok, fmt.Sprintf("installed %d components, %d failed", len(result.Successful), len(result.Failed)))
	} else {
		span.SetStatus(codes.Error, fmt.Sprintf("all %d components failed to install", len(result.Failed)))
	}

	span.SetAttributes(
		attribute.Int("gibson.components_successful", len(result.Successful)),
		attribute.Int("gibson.components_failed", len(result.Failed)),
	)

	return result, nil
}

// installSingleComponent installs a single component from a repository directory.
// This is optimized for repositories that contain only one component (no discovery needed).
// It validates that the manifest kind matches the expected kind, builds the component if needed,
// and registers it with the component registry.
func (i *DefaultInstaller) installSingleComponent(ctx context.Context, repoDir string, manifest *Manifest, kind ComponentKind, opts InstallOptions) (*InstallAllResult, error) {
	// Start tracing span
	ctx, span := i.tracer.Start(ctx, "component.install_single_component")
	defer span.End()

	start := time.Now()
	result := &InstallAllResult{
		RepoURL:    repoDir,
		Successful: make([]InstallResult, 0),
		Failed:     make([]InstallFailure, 0),
	}

	// Add component metadata to span
	span.SetAttributes(
		attribute.String(AttrComponentKind, kind.String()),
		attribute.String(AttrComponentName, manifest.Name),
	)

	// Step 1: Validate ComponentKind(manifest.Kind) == kind
	// Convert manifest.Kind (string) to ComponentKind and compare
	manifestKind := ComponentKind(manifest.Kind)
	if manifestKind != kind {
		err := fmt.Errorf("manifest kind %q does not match expected %q", manifest.Kind, kind.String())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(ErrorAttributes(err, "validate_manifest_kind")...)
		result.Failed = append(result.Failed, InstallFailure{
			Path:  repoDir,
			Name:  manifest.Name,
			Error: err,
		})
		result.ComponentsFound = 1
		result.Duration = time.Since(start)
		return result, err
	}

	// Step 2: Build if manifest.Build != nil && !opts.SkipBuild
	var buildOutput string
	if !opts.SkipBuild && manifest.Build != nil {
		buildStart := time.Now()
		buildResult, err := i.buildComponent(ctx, repoDir, manifest, opts.Verbose)
		buildDuration := time.Since(buildStart)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "build_component")...)
			result.Failed = append(result.Failed, InstallFailure{
				Path:  repoDir,
				Name:  manifest.Name,
				Error: err,
			})
			result.ComponentsFound = 1
			result.Duration = time.Since(start)
			return result, err
		}
		buildOutput = buildResult.Stdout + "\n" + buildResult.Stderr

		// Add build metrics to span
		span.SetAttributes(
			attribute.String(AttrBuildCommand, manifest.Build.Command),
			attribute.Int64(AttrBuildDuration, buildDuration.Milliseconds()),
		)
	}

	// Get the git version (commit hash)
	version, err := i.git.GetVersion(repoDir)
	if err != nil {
		// Use manifest version as fallback
		version = manifest.Version
	}

	// Check if component already exists (idempotency check)
	// This prevents unnecessary artifact copying and rollback operations
	if !opts.Force && i.store != nil {
		if existing, err := i.store.GetByName(ctx, kind, manifest.Name); err == nil && existing != nil {
			// Check if this is an orphaned component (DB entry exists but binary is missing)
			if i.isOrphanedComponent(existing) {
				// Clean up the orphaned entry and proceed with installation
				if cleanupErr := i.cleanupOrphanedComponent(ctx, kind, manifest.Name, existing); cleanupErr != nil {
					// Cleanup failed - return error result
					span.RecordError(cleanupErr)
					span.SetStatus(codes.Error, cleanupErr.Error())
					span.SetAttributes(ErrorAttributes(cleanupErr, "cleanup_orphaned")...)
					result.Failed = append(result.Failed, InstallFailure{
						Path:  repoDir,
						Name:  manifest.Name,
						Error: cleanupErr,
					})
					result.ComponentsFound = 1
					result.Duration = time.Since(start)
					return result, cleanupErr
				}
				// Cleanup succeeded - proceed with installation
			} else {
				// Valid existing component - skip installation and return it
				result.Successful = append(result.Successful, InstallResult{
					Component:   existing,
					Path:        repoDir,
					Duration:    time.Since(start),
					BuildOutput: "",
					Installed:   false, // Not newly installed
					Updated:     false,
				})
				result.ComponentsFound = 1
				result.Duration = time.Since(start)
				span.SetStatus(codes.Ok, "component already installed, skipped")
				span.SetAttributes(
					ComponentAttributes(existing)...,
				)
				return result, nil
			}
		}
	}

	// If Force is set and component exists, delete it first
	if opts.Force && i.store != nil {
		_ = i.store.Delete(ctx, kind, manifest.Name)
	}

	// Determine the source directory for artifacts
	// If component has build.workdir, artifacts are there; otherwise use repoDir
	artifactSourceDir := repoDir
	if manifest.Build != nil && manifest.Build.WorkDir != "" {
		artifactSourceDir = filepath.Join(repoDir, manifest.Build.WorkDir)
	}

	// Create install context for rollback tracking
	installCtx := &installContext{
		componentKind: kind,
		componentName: manifest.Name,
	}

	// Copy artifacts to bin/ directory
	var binPath string
	if manifest.Build != nil && len(manifest.Build.Artifacts) > 0 {
		// Verify all artifacts exist before attempting to copy
		if err := i.verifyArtifactsExist(manifest.Build.Artifacts, artifactSourceDir); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(ErrorAttributes(err, "verify_artifacts")...)
			result.Failed = append(result.Failed, InstallFailure{
				Path:  repoDir,
				Name:  manifest.Name,
				Error: err,
			})
			result.ComponentsFound = 1
			result.Duration = time.Since(start)
			return result, err
		}

		binPath, err = i.copyArtifactsToBin(kind, manifest.Build.Artifacts, artifactSourceDir)
		if err != nil {
			validationErr := WrapComponentError(ErrCodeLoadFailed, "failed to copy artifacts to bin", err).
				WithComponent(manifest.Name)
			span.RecordError(validationErr)
			span.SetStatus(codes.Error, validationErr.Error())
			span.SetAttributes(ErrorAttributes(validationErr, "copy_artifacts")...)
			result.Failed = append(result.Failed, InstallFailure{
				Path:  repoDir,
				Name:  manifest.Name,
				Error: validationErr,
			})
			result.ComponentsFound = 1
			result.Duration = time.Since(start)
			return result, validationErr
		}

		// Track copied artifact for potential rollback
		installCtx.copiedArtifacts = append(installCtx.copiedArtifacts, binPath)
	} else {
		// No artifacts specified - this might be OK for some components
		// Use empty binPath (component might be library, script, etc.)
		binPath = ""
	}

	// Step 3: Create Component with new directory structure
	// RepoPath points to the cloned repository in _repos/
	// BinPath points to the artifact in bin/
	component := &Component{
		Kind:      kind,
		Name:      manifest.Name,
		Version:   version,
		RepoPath:  repoDir, // Path to component in _repos/{repo-name}
		BinPath:   binPath, // Path to binary in bin/{artifact-name}
		Source:    ComponentSourceExternal,
		Status:    ComponentStatusAvailable,
		Manifest:  manifest,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Validate component
	if err := component.Validate(); err != nil {
		// Rollback copied artifacts on failure
		installCtx.rollback(i.store, ctx)
		validationErr := NewValidationFailedError("component validation failed", err)
		span.RecordError(validationErr)
		span.SetStatus(codes.Error, validationErr.Error())
		span.SetAttributes(ErrorAttributes(validationErr, "validate_component")...)
		result.Failed = append(result.Failed, InstallFailure{
			Path:  repoDir,
			Name:  manifest.Name,
			Error: validationErr,
		})
		result.ComponentsFound = 1
		result.Duration = time.Since(start)
		return result, validationErr
	}

	// Step 4: Register with i.store.Create()
	if !opts.SkipRegister && i.store != nil {
		if err := i.store.Create(ctx, component); err != nil {
			// Rollback copied artifacts on failure
			installCtx.rollback(i.store, ctx)
			registerErr := WrapComponentError(ErrCodeLoadFailed, "failed to register component", err).
				WithComponent(manifest.Name)
			span.RecordError(registerErr)
			span.SetStatus(codes.Error, registerErr.Error())
			span.SetAttributes(ErrorAttributes(registerErr, "register_component")...)
			result.Failed = append(result.Failed, InstallFailure{
				Path:  repoDir,
				Name:  manifest.Name,
				Error: registerErr,
			})
			result.ComponentsFound = 1
			result.Duration = time.Since(start)
			return result, registerErr
		}
	}

	// Create successful install result
	installResult := InstallResult{
		Component:   component,
		Path:        repoDir,
		Duration:    time.Since(start),
		BuildOutput: buildOutput,
		Installed:   true,
		Updated:     false,
	}

	result.Successful = append(result.Successful, installResult)

	// Step 5: Return result with ComponentsFound=1
	result.ComponentsFound = 1
	result.Duration = time.Since(start)

	// Record successful installation
	span.SetStatus(codes.Ok, "single component installed successfully")
	span.SetAttributes(
		ComponentAttributes(component)...,
	)
	span.SetAttributes(
		attribute.Int("gibson.components_successful", 1),
		attribute.Int("gibson.components_failed", 0),
	)

	return result, nil
}

// Update updates an installed component to the latest version
func (i *DefaultInstaller) Update(ctx context.Context, kind ComponentKind, name string, opts UpdateOptions) (*UpdateResult, error) {
	// Start tracing span
	ctx, span := i.tracer.Start(ctx, SpanComponentUpdate)
	defer span.End()

	// Add component metadata to span
	span.SetAttributes(
		attribute.String(AttrComponentKind, kind.String()),
		attribute.String(AttrComponentName, name),
	)

	start := time.Now()
	result := &UpdateResult{}

	// Set default timeout if not specified
	if opts.Timeout == 0 {
		opts.Timeout = DefaultInstallTimeout
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Validate component kind
	if !kind.IsValid() {
		err := NewInvalidKindError(kind.String())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(ErrorAttributes(err, "validate_kind")...)
		return result, err
	}

	// Get component path
	componentDir := filepath.Join(i.homeDir, kind.String()+"s", name)

	// Verify component exists
	if _, err := os.Stat(componentDir); os.IsNotExist(err) {
		notFoundErr := NewComponentNotFoundError(name).
			WithContext("path", componentDir)
		span.RecordError(notFoundErr)
		span.SetStatus(codes.Error, notFoundErr.Error())
		span.SetAttributes(ErrorAttributes(notFoundErr, "check_exists")...)
		return result, notFoundErr
	}

	// Get current component from DAO if available
	var wasRunning bool
	if i.store != nil {
		if comp, err := i.store.GetByName(ctx, kind, name); err == nil && comp != nil {
			result.OldVersion = comp.Version
			wasRunning = comp.IsRunning()

			// Step 1: Stop component if running
			if wasRunning && i.lifecycle != nil {
				span.AddEvent("stopping running component before upgrade", trace.WithAttributes(
					attribute.String("component.name", name),
					attribute.Int("component.pid", comp.PID),
				))

				// Create a timeout context for the stop operation
				stopCtx, stopCancel := context.WithTimeout(ctx, DefaultShutdownTimeout)
				defer stopCancel()

				if err := i.lifecycle.StopComponent(stopCtx, comp); err != nil {
					// Log the error but continue with upgrade
					// The component may have already stopped or the process may be dead
					span.AddEvent("failed to stop component gracefully", trace.WithAttributes(
						attribute.String("error", err.Error()),
					))
				} else {
					span.AddEvent("component stopped successfully", nil)
				}
			}
		}
	}

	// If we don't have old version from registry, try to get it from git
	if result.OldVersion == "" {
		if version, err := i.git.GetVersion(componentDir); err == nil {
			result.OldVersion = version
		}
	}

	// Step 2: Pull latest changes
	if err := i.git.Pull(componentDir); err != nil {
		return result, WrapComponentError(ErrCodeLoadFailed, "failed to pull latest changes", err).
			WithComponent(name)
	}

	// Get new version
	newVersion, err := i.git.GetVersion(componentDir)
	if err != nil {
		return result, WrapComponentError(ErrCodeLoadFailed, "failed to get new version", err).
			WithComponent(name)
	}
	result.NewVersion = newVersion

	// Check if there were any changes
	if result.OldVersion == result.NewVersion {
		result.Duration = time.Since(start)
		result.Updated = false
		return result, nil
	}

	// Step 3: Load manifest
	manifestPath := filepath.Join(componentDir, ManifestFileName)
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return result, err
	}

	// Check dependencies
	if err := i.checkDependencies(ctx, manifest); err != nil {
		return result, err
	}

	// Step 4: Rebuild component (unless SkipBuild is set)
	var buildOutput string
	var binPath string
	if !opts.SkipBuild && manifest.Build != nil {
		buildResult, err := i.buildComponent(ctx, componentDir, manifest, opts.Verbose)
		if err != nil {
			return result, err
		}
		buildOutput = buildResult.Stdout + "\n" + buildResult.Stderr

		// Copy artifacts to bin directory after successful build
		if len(manifest.Build.Artifacts) > 0 {
			binPath, err = i.copyArtifactsToBin(kind, manifest.Build.Artifacts, componentDir)
			if err != nil {
				return result, WrapComponentError(ErrCodeLoadFailed, "failed to copy artifacts", err).
					WithComponent(name)
			}
		}
	}
	result.BuildOutput = buildOutput

	// Step 5: Update component in database
	if i.store != nil {
		component := &Component{
			Kind:      kind,
			Name:      name,
			Version:   newVersion,
			RepoPath:  componentDir,
			BinPath:   binPath,
			Source:    ComponentSourceExternal,
			Status:    ComponentStatusAvailable,
			Manifest:  manifest,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Delete old version
		_ = i.store.Delete(ctx, kind, name)

		// Create new version
		if err := i.store.Create(ctx, component); err != nil {
			return result, WrapComponentError(ErrCodeLoadFailed, "failed to re-register component", err).
				WithComponent(name)
		}

		result.Component = component
	}

	// Step 6: Optionally restart if it was running
	if opts.Restart && wasRunning {
		// Note: Actual restart logic would depend on the component manager
		// For now, we just mark it as needing restart
		result.Restarted = false // Would be true after actual restart
	}

	result.Duration = time.Since(start)
	result.Updated = true

	// Record successful update
	span.SetStatus(codes.Ok, "component updated successfully")
	span.SetAttributes(UpdateResultAttributes(result)...)
	if result.Component != nil {
		span.SetAttributes(ComponentAttributes(result.Component)...)
	}

	return result, nil
}

// UpdateAll updates all installed components of a specific kind
func (i *DefaultInstaller) UpdateAll(ctx context.Context, kind ComponentKind, opts UpdateOptions) ([]UpdateResult, error) {
	// Validate component kind
	if !kind.IsValid() {
		return nil, NewInvalidKindError(kind.String())
	}

	// Get all components of this kind from DAO
	var components []*Component
	var err error
	if i.store != nil {
		components, err = i.store.List(ctx, kind)
		if err != nil {
			return nil, err
		}
	} else {
		// If no DAO, scan filesystem
		components, err = i.scanComponents(kind)
		if err != nil {
			return nil, err
		}
	}

	// Update each component
	results := make([]UpdateResult, 0, len(components))
	for _, comp := range components {
		result, err := i.Update(ctx, kind, comp.Name, opts)
		if err != nil {
			// Continue with other components even if one fails
			result = &UpdateResult{
				Component: comp,
				Path:      comp.RepoPath,
				Updated:   false,
			}
		}
		results = append(results, *result)
	}

	return results, nil
}

// Uninstall removes an installed component
func (i *DefaultInstaller) Uninstall(ctx context.Context, kind ComponentKind, name string) (*UninstallResult, error) {
	// Start tracing span
	ctx, span := i.tracer.Start(ctx, SpanComponentUninstall)
	defer span.End()

	// Add component metadata to span
	span.SetAttributes(
		attribute.String(AttrComponentKind, kind.String()),
		attribute.String(AttrComponentName, name),
	)

	start := time.Now()
	result := &UninstallResult{
		Name: name,
		Kind: kind,
	}

	// Validate component kind
	if !kind.IsValid() {
		err := NewInvalidKindError(kind.String())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(ErrorAttributes(err, "validate_kind")...)
		return result, err
	}

	// Step 1: Get component from database to retrieve BinPath and RepoPath
	var comp *Component
	if i.store != nil {
		var err error
		comp, err = i.store.GetByName(ctx, kind, name)
		if err != nil {
			// Component not found in database
			notFoundErr := NewComponentNotFoundError(name)
			span.RecordError(notFoundErr)
			span.SetStatus(codes.Error, notFoundErr.Error())
			span.SetAttributes(ErrorAttributes(notFoundErr, "get_component")...)
			return result, notFoundErr
		}

		// Check if component is running
		if comp.IsRunning() {
			result.WasRunning = true
			span.SetAttributes(attribute.Bool("gibson.component.was_running", true))

			// Stop component before uninstalling
			if i.lifecycle != nil {
				span.AddEvent("stopping running component before uninstall", trace.WithAttributes(
					attribute.String("component.name", name),
					attribute.Int("component.pid", comp.PID),
				))

				// Create a timeout context for the stop operation
				stopCtx, stopCancel := context.WithTimeout(ctx, DefaultShutdownTimeout)
				defer stopCancel()

				if err := i.lifecycle.StopComponent(stopCtx, comp); err != nil {
					// Log error but continue with uninstall
					// The process may already be dead
					span.AddEvent("failed to stop component gracefully", trace.WithAttributes(
						attribute.String("error", err.Error()),
					))
					result.WasStopped = false
				} else {
					span.AddEvent("component stopped successfully", nil)
					result.WasStopped = true
				}
			} else {
				result.WasStopped = false
			}
		}
	} else {
		// Fallback to legacy path if no DAO
		componentDir := filepath.Join(i.homeDir, kind.String()+"s", name)

		// Verify component exists
		if _, err := os.Stat(componentDir); os.IsNotExist(err) {
			notFoundErr := NewComponentNotFoundError(name).
				WithContext("path", componentDir)
			span.RecordError(notFoundErr)
			span.SetStatus(codes.Error, notFoundErr.Error())
			span.SetAttributes(ErrorAttributes(notFoundErr, "check_exists")...)
			return result, notFoundErr
		}
	}

	// Step 2: Remove the binary file at BinPath (if it exists)
	if comp != nil && comp.BinPath != "" {
		if err := os.Remove(comp.BinPath); err != nil && !os.IsNotExist(err) {
			// Log warning but don't fail - binary might already be missing
			span.AddEvent("failed to remove binary", trace.WithAttributes(
				attribute.String("path", comp.BinPath),
				attribute.String("error", err.Error()),
			))
		} else if err == nil {
			span.AddEvent("removed binary", trace.WithAttributes(
				attribute.String("path", comp.BinPath),
			))
		}
	}

	// Step 2.5: Unregister agent taxonomy extension (agents only)
	if kind == ComponentKindAgent {
		i.unregisterTaxonomyExtension(ctx, name, span)
	}

	// Step 3: Delete from database
	if i.store != nil {
		if err := i.store.Delete(ctx, kind, name); err != nil {
			// Log error but continue with cleanup
			span.AddEvent("failed to delete from database", trace.WithAttributes(
				attribute.String("error", err.Error()),
			))
		}
	}

	// Step 4: Optionally clean up repository if no other components use it
	if comp != nil && comp.RepoPath != "" {
		// Check if other components use the same repository
		shouldRemoveRepo := true

		// First, determine the actual repository root for this component
		// For single-component repos: RepoPath IS the repo root (e.g., _repos/network-recon)
		// For mono-repos: RepoPath is a subdirectory (e.g., _repos/mono-repo/agents/my-agent)
		reposDir := i.getReposDir(kind)
		compRepoRoot := i.getRepoRoot(comp.RepoPath, reposDir)

		if i.store != nil {
			// Get all components of this kind
			allComponents, err := i.store.List(ctx, kind)
			if err == nil {
				// Check if any other component shares the same repository root
				for _, otherComp := range allComponents {
					if otherComp.Name != name && otherComp.RepoPath != "" {
						otherRepoRoot := i.getRepoRoot(otherComp.RepoPath, reposDir)
						// Components share a repo only if they have the same repo root
						if compRepoRoot == otherRepoRoot {
							shouldRemoveRepo = false
							span.AddEvent("repository shared with other components", trace.WithAttributes(
								attribute.String("repo_path", comp.RepoPath),
								attribute.String("repo_root", compRepoRoot),
								attribute.String("shared_with", otherComp.Name),
							))
							break
						}
					}
				}
			}
		}

		// Remove repository if no other components use it
		if shouldRemoveRepo {
			// Use the repo root we already calculated above
			// Remove the repository directory
			if err := os.RemoveAll(compRepoRoot); err != nil && !os.IsNotExist(err) {
				// Log warning but don't fail - partial cleanup is acceptable
				span.AddEvent("failed to remove repository", trace.WithAttributes(
					attribute.String("path", compRepoRoot),
					attribute.String("error", err.Error()),
				))
			} else if err == nil {
				span.AddEvent("removed repository", trace.WithAttributes(
					attribute.String("path", compRepoRoot),
				))
			}
		}
	}

	result.Duration = time.Since(start)

	// Record successful uninstall
	span.SetStatus(codes.Ok, "component uninstalled successfully")
	span.SetAttributes(UninstallResultAttributes(result)...)

	return result, nil
}

// checkDependencies validates that all component dependencies are satisfied
func (i *DefaultInstaller) checkDependencies(ctx context.Context, manifest *Manifest) error {
	if manifest.Dependencies == nil || !manifest.Dependencies.HasDependencies() {
		return nil
	}

	deps := manifest.Dependencies

	// Check system dependencies
	for _, sysDep := range deps.GetSystem() {
		// For now, just check if the command exists
		// In a real implementation, we would also check versions
		if err := i.checkSystemDependency(sysDep); err != nil {
			return NewDependencyFailedError(manifest.Name, sysDep, err, false)
		}
	}

	// Check component dependencies
	if i.store != nil {
		for _, compDep := range deps.GetComponents() {
			if err := i.checkComponentDependency(compDep); err != nil {
				return NewDependencyFailedError(manifest.Name, compDep, err, false)
			}
		}
	}

	// Check required environment variables
	for key := range deps.GetEnv() {
		if os.Getenv(key) == "" {
			return NewDependencyFailedError(manifest.Name, key,
				fmt.Errorf("required environment variable %s not set", key), false)
		}
	}

	return nil
}

// checkSystemDependency checks if a system dependency is available
func (i *DefaultInstaller) checkSystemDependency(dep string) error {
	// Use exec.LookPath to check if the binary exists in PATH
	path, err := exec.LookPath(dep)
	if err != nil {
		// Dependency not found in PATH
		return fmt.Errorf("system dependency '%s' not found in PATH: install it using your package manager (e.g., apt install %s, brew install %s, yum install %s)", dep, dep, dep, dep)
	}

	// Dependency found
	_ = path // Path is available if needed for debugging
	return nil
}

// checkComponentDependency checks if a component dependency is satisfied
func (i *DefaultInstaller) checkComponentDependency(dep string) error {
	// Parse dependency format: name@version
	// For now, just check if component exists
	// In a real implementation, we would also check version compatibility
	return nil
}

// buildComponent builds a component using its build configuration
func (i *DefaultInstaller) buildComponent(ctx context.Context, componentDir string, manifest *Manifest, verbose bool) (*build.BuildResult, error) {
	// Prepare default build configuration (make build)
	buildConfig := build.BuildConfig{
		WorkDir:    componentDir,
		Command:    "make",
		Args:       []string{"build"},
		OutputPath: "", // Will be determined from build artifacts
		Env:        nil,
		Verbose:    verbose,
	}

	// Override with manifest build config if specified
	if manifest.Build != nil {
		buildCfg := manifest.Build

		// Use manifest environment variables
		buildConfig.Env = buildCfg.GetEnv()

		// Override with manifest build command if specified
		if buildCfg.Command != "" {
			// Parse the command string into command and arguments
			parts := strings.Fields(buildCfg.Command)
			if len(parts) > 0 {
				buildConfig.Command = parts[0]
				if len(parts) > 1 {
					buildConfig.Args = parts[1:]
				} else {
					buildConfig.Args = []string{}
				}
			}
		}

		// Set working directory if specified
		if buildCfg.WorkDir != "" {
			buildConfig.WorkDir = filepath.Join(componentDir, buildCfg.WorkDir)
		}
	}

	// Build with timeout
	buildCtx, cancel := context.WithTimeout(ctx, DefaultBuildTimeout)
	defer cancel()

	result, err := i.builder.Build(buildCtx, buildConfig, manifest.Name, manifest.Version, "dev")
	if err != nil {
		compErr := WrapComponentError(ErrCodeLoadFailed, "build failed", err).
			WithComponent(manifest.Name).
			WithContext("build_command", buildConfig.Command+" "+strings.Join(buildConfig.Args, " ")).
			WithContext("work_dir", buildConfig.WorkDir)
		// Include build output in error context for debugging
		if result != nil {
			if result.Stdout != "" {
				compErr.WithContext("stdout", result.Stdout)
			}
			if result.Stderr != "" {
				compErr.WithContext("stderr", result.Stderr)
			}
		}
		return result, compErr
	}

	return result, nil
}

// copyDir copies a directory recursively from src to dst
func copyDir(src, dst string) error {
	// Get source directory info
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	// Read source directory entries
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			// Recursively copy subdirectory
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			// Copy file
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
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

// scanComponents scans the filesystem for installed components
func (i *DefaultInstaller) scanComponents(kind ComponentKind) ([]*Component, error) {
	componentsDir := filepath.Join(i.homeDir, kind.String()+"s")

	// Check if directory exists
	if _, err := os.Stat(componentsDir); os.IsNotExist(err) {
		return []*Component{}, nil
	}

	// Read directory entries
	entries, err := os.ReadDir(componentsDir)
	if err != nil {
		return nil, WrapComponentError(ErrCodeLoadFailed, "failed to read components directory", err)
	}

	// Load each component
	components := make([]*Component, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		componentDir := filepath.Join(componentsDir, entry.Name())
		manifestPath := filepath.Join(componentDir, ManifestFileName)

		// Load manifest
		manifest, err := LoadManifest(manifestPath)
		if err != nil {
			// Skip components with invalid manifests
			continue
		}

		// Get version from git
		version := manifest.Version
		if gitVersion, err := i.git.GetVersion(componentDir); err == nil {
			version = gitVersion
		}

		// Calculate BinPath based on artifacts
		var binPath string
		if manifest.Build != nil && len(manifest.Build.Artifacts) > 0 {
			// Use the first artifact as the primary binary
			primaryArtifact := manifest.Build.Artifacts[0]
			binDir := filepath.Join(i.homeDir, "bin")
			binPath = filepath.Join(binDir, primaryArtifact)
		}

		component := &Component{
			Kind:      kind,
			Name:      entry.Name(),
			Version:   version,
			RepoPath:  componentDir,
			BinPath:   binPath,
			Source:    ComponentSourceExternal,
			Status:    ComponentStatusAvailable,
			Manifest:  manifest,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		components = append(components, component)
	}

	return components, nil
}

// getBinDir returns the binary directory for a specific component kind.
// Returns ~/.gibson/{kind}s/bin/ (e.g., ~/.gibson/agents/bin/, ~/.gibson/tools/bin/)
func (i *DefaultInstaller) getBinDir(kind ComponentKind) string {
	return filepath.Join(i.homeDir, kind.String()+"s", "bin")
}

// getReposDir returns the repositories directory for a specific component kind.
// Returns ~/.gibson/{kind}s/_repos/ (e.g., ~/.gibson/agents/_repos/, ~/.gibson/tools/_repos/)
func (i *DefaultInstaller) getReposDir(kind ComponentKind) string {
	return filepath.Join(i.homeDir, kind.String()+"s", "_repos")
}

// getRepoRoot determines the actual git repository root for a component path.
// For single-component repos: returns the component path itself (e.g., _repos/network-recon)
// For mono-repos: returns the first directory under _repos/ (e.g., _repos/tools for _repos/tools/nmap)
// If the path is not under reposDir, returns the path unchanged.
func (i *DefaultInstaller) getRepoRoot(componentPath, reposDir string) string {
	// If not under _repos/, return as-is
	if !strings.HasPrefix(componentPath, reposDir) {
		return componentPath
	}

	// Get the relative path from _repos/
	relPath, err := filepath.Rel(reposDir, componentPath)
	if err != nil || relPath == "." {
		return componentPath
	}

	// Get the first path component (the actual repo directory name)
	pathParts := strings.Split(relPath, string(filepath.Separator))
	if len(pathParts) == 0 {
		return componentPath
	}

	// Return the full path to the repo root
	return filepath.Join(reposDir, pathParts[0])
}

// verifyArtifactsExist checks that all specified artifacts exist at the source directory.
// This is called before copying artifacts to detect build failures early with clear error messages.
// Returns nil if all artifacts exist, or a ComponentError with details about missing artifacts.
func (i *DefaultInstaller) verifyArtifactsExist(artifacts []string, sourceDir string) error {
	var missingArtifacts []string
	var searchedPaths []string

	for _, artifact := range artifacts {
		fullPath := filepath.Join(sourceDir, artifact)
		searchedPaths = append(searchedPaths, fullPath)

		if _, err := os.Stat(fullPath); err != nil {
			if os.IsNotExist(err) {
				missingArtifacts = append(missingArtifacts, artifact)
			}
			// Ignore other errors (like permission issues) - they'll be caught during copy
		}
	}

	if len(missingArtifacts) > 0 {
		return WrapComponentError(ErrCodeLoadFailed, "artifacts not found after build", nil).
			WithContext("missing_artifacts", strings.Join(missingArtifacts, ", ")).
			WithContext("searched_paths", strings.Join(searchedPaths, ", ")).
			WithContext("source_dir", sourceDir)
	}

	return nil
}

// copyArtifactsToBin copies build artifacts from sourceDir to the bin directory for the specified component kind.
// It creates the bin directory if it doesn't exist, copies all artifacts preserving file permissions,
// and returns the path to the primary artifact (first in the list).
// Returns the absolute path to the primary artifact in the bin directory.
func (i *DefaultInstaller) copyArtifactsToBin(kind ComponentKind, artifacts []string, sourceDir string) (string, error) {
	if len(artifacts) == 0 {
		return "", fmt.Errorf("no artifacts to copy")
	}

	// Get bin directory and ensure it exists
	binDir := i.getBinDir(kind)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", WrapComponentError(ErrCodePermissionDenied, "failed to create bin directory", err).
			WithContext("path", binDir)
	}

	// Copy all artifacts to bin directory
	var primaryArtifactPath string
	for idx, artifact := range artifacts {
		// Source path is relative to sourceDir
		srcPath := filepath.Join(sourceDir, artifact)

		// Destination path uses just the artifact filename (not the full path)
		dstPath := filepath.Join(binDir, filepath.Base(artifact))

		// Copy the file
		if err := copyFile(srcPath, dstPath); err != nil {
			return "", WrapComponentError(ErrCodeLoadFailed, "failed to copy artifact", err).
				WithContext("artifact", artifact).
				WithContext("source", srcPath).
				WithContext("destination", dstPath).
				WithContext("source_dir", sourceDir).
				WithContext("remediation", "verify build completed successfully and artifact exists at source path")
		}

		// First artifact is the primary artifact
		if idx == 0 {
			primaryArtifactPath = dstPath
		}
	}

	return primaryArtifactPath, nil
}

// isOrphanedComponent checks if a component database record is orphaned
// (i.e., the DB record exists but the binary file is missing).
// Returns false if:
//   - comp is nil
//   - comp.BinPath is empty (script-based components without binaries)
//   - BinPath file exists or there's an error other than "not exist"
//
// Returns true if:
//   - BinPath is set but the file doesn't exist
func (i *DefaultInstaller) isOrphanedComponent(comp *Component) bool {
	if comp == nil {
		return false
	}

	if comp.BinPath == "" {
		return false
	}

	_, err := os.Stat(comp.BinPath)
	if os.IsNotExist(err) {
		return true
	}

	return false
}

// cleanupOrphanedComponent cleans up an orphaned component database entry
// (i.e., the DB record exists but the binary file is missing).
// Returns nil if the component is not orphaned or if cleanup succeeds.
// Returns a ComponentError if the database delete operation fails.
func (i *DefaultInstaller) cleanupOrphanedComponent(ctx context.Context, kind ComponentKind, name string, existing *Component) error {
	// Check if component is actually orphaned
	if !i.isOrphanedComponent(existing) {
		return nil
	}

	// Get span from context for tracing
	span := trace.SpanFromContext(ctx)

	// Add span event with component details
	span.AddEvent("cleaning up orphaned component", trace.WithAttributes(
		attribute.String("component.name", name),
		attribute.String("component.bin_path", existing.BinPath),
	))

	// Delete the orphaned entry from the database
	if i.store != nil {
		if err := i.store.Delete(ctx, kind, name); err != nil {
			return WrapComponentError(ErrCodeLoadFailed, "failed to delete orphaned component", err).
				WithComponent(name)
		}
	}

	return nil
}

// detectComponentBinary looks for an executable binary in the build directory.
// It checks for common binary naming patterns in order of preference:
//  1. Exact match: {componentName} (e.g., "network-recon")
//  2. In bin/ subdirectory: bin/{componentName}
//  3. Any executable file matching the component name pattern
//
// Returns the relative path to the binary from buildDir, or empty string if not found.
func (i *DefaultInstaller) detectComponentBinary(componentName string, buildDir string) string {
	// Check 1: Exact match in build directory root
	exactPath := filepath.Join(buildDir, componentName)
	if i.isExecutableFile(exactPath) {
		return componentName
	}

	// Check 2: In bin/ subdirectory
	binSubdirPath := filepath.Join(buildDir, "bin", componentName)
	if i.isExecutableFile(binSubdirPath) {
		return filepath.Join("bin", componentName)
	}

	// Check 3: Look for any executable in build directory that matches component name
	entries, err := os.ReadDir(buildDir)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Check if filename contains the component name and is executable
		if strings.Contains(entry.Name(), componentName) {
			fullPath := filepath.Join(buildDir, entry.Name())
			if i.isExecutableFile(fullPath) {
				return entry.Name()
			}
		}
	}

	return ""
}

// isExecutableFile checks if a path exists and is an executable file.
func (i *DefaultInstaller) isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return false
	}
	// Check if file has any execute bit set
	return info.Mode()&0111 != 0
}

// hasMakefileBuildTarget checks if the directory contains a Makefile with a build target.
// This enables auto-build for components that have a Makefile but no explicit build config.
func (i *DefaultInstaller) hasMakefileBuildTarget(dir string) bool {
	makefilePath := filepath.Join(dir, "Makefile")
	content, err := os.ReadFile(makefilePath)
	if err != nil {
		return false
	}

	// Check if Makefile contains a "build:" target
	// This is a simple check - looks for "build:" at the start of a line
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "build:") || trimmed == "build" {
			return true
		}
	}
	return false
}

// copyRepoBuildArtifacts copies executable files from a repository's bin/ directory
// to the Gibson bin directory (~/.gibson/{kind}s/bin/).
// This handles the common pattern where repository-level builds output all artifacts
// to a single bin/ directory at the repository root.
func (i *DefaultInstaller) copyRepoBuildArtifacts(kind ComponentKind, repoDir string) error {
	// Check if repo has a bin/ directory
	repoBinDir := filepath.Join(repoDir, "bin")
	if _, err := os.Stat(repoBinDir); os.IsNotExist(err) {
		// No bin directory - nothing to copy
		return nil
	}

	// Get the destination bin directory
	destBinDir := i.getBinDir(kind)
	if err := os.MkdirAll(destBinDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}

	// Read all files in the repo's bin directory
	entries, err := os.ReadDir(repoBinDir)
	if err != nil {
		return fmt.Errorf("failed to read repo bin directory: %w", err)
	}

	// Copy each executable file
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(repoBinDir, entry.Name())
		dstPath := filepath.Join(destBinDir, entry.Name())

		// Check if file is executable
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Only copy executable files (has any execute bit set)
		if info.Mode()&0111 == 0 {
			continue
		}

		// Copy the file
		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// extractRepoName extracts the repository name from a git repository URL.
// It handles both HTTPS and SSH URL formats, with or without .git suffix.
// Examples:
//   - "https://github.com/zeroroot-ai/gibson-tools-official.git" -> "gibson-tools-official"
//   - "git@github.com:zeroroot-ai/gibson-tools-official.git" -> "gibson-tools-official"
//   - "https://github.com/zeroroot-ai/gibson-tools-official" -> "gibson-tools-official"
//   - "https://github.com/zeroroot-ai/gibson-tools-official/" -> "gibson-tools-official"
func extractRepoName(repoURL string) string {
	// Remove trailing slashes
	repoURL = strings.TrimRight(repoURL, "/")

	// Extract the last path component
	var pathPart string

	// Handle SSH URLs (git@github.com:user/repo.git)
	if strings.Contains(repoURL, ":") && strings.Contains(repoURL, "@") {
		// SSH format: split by colon and take the part after it
		parts := strings.Split(repoURL, ":")
		if len(parts) > 1 {
			pathPart = parts[len(parts)-1]
		}
	} else {
		// HTTPS format: use the whole URL
		pathPart = repoURL
	}

	// Now extract the last component from the path (after the last /)
	parts := strings.Split(pathPart, "/")
	lastPart := ""
	if len(parts) > 0 {
		lastPart = parts[len(parts)-1]
	}

	// Remove .git suffix if present
	lastPart = strings.TrimSuffix(lastPart, ".git")

	return lastPart
}

// buildAtPath builds a component at the specified directory using the given build configuration.
// This is similar to buildComponent but operates on an explicit directory path rather than
// deriving it from the manifest. It uses the build configuration from the manifest, defaulting
// to "make build" if no command is specified.
func (i *DefaultInstaller) buildAtPath(ctx context.Context, dir string, buildCfg *BuildConfig, verbose bool) (*build.BuildResult, error) {
	// Prepare build configuration with defaults
	buildConfig := build.BuildConfig{
		WorkDir:    dir,
		Command:    "make",
		Args:       []string{"build"},
		OutputPath: "", // Will be determined from build artifacts
		Env:        nil,
		Verbose:    verbose,
	}

	// If build config is provided, use its settings
	if buildCfg != nil {
		buildConfig.Env = buildCfg.GetEnv()

		// Override with manifest build command if specified
		if buildCfg.Command != "" {
			// Parse the command string into command and arguments
			parts := strings.Fields(buildCfg.Command)
			if len(parts) > 0 {
				buildConfig.Command = parts[0]
				if len(parts) > 1 {
					buildConfig.Args = parts[1:]
				} else {
					buildConfig.Args = []string{}
				}
			}
		}

		// Set working directory if specified in build config
		if buildCfg.WorkDir != "" {
			buildConfig.WorkDir = filepath.Join(dir, buildCfg.WorkDir)
		}
	}

	// Build with timeout
	buildCtx, cancel := context.WithTimeout(ctx, DefaultBuildTimeout)
	defer cancel()

	// Execute the build
	result, err := i.builder.Build(buildCtx, buildConfig, "", "", "dev")
	if err != nil {
		compErr := WrapComponentError(ErrCodeLoadFailed, "build failed", err).
			WithContext("build_command", buildConfig.Command+" "+strings.Join(buildConfig.Args, " ")).
			WithContext("work_dir", buildConfig.WorkDir)
		// Include build output in error context for debugging
		if result != nil {
			if result.Stdout != "" {
				compErr.WithContext("stdout", result.Stdout)
			}
			if result.Stderr != "" {
				compErr.WithContext("stderr", result.Stderr)
			}
		}
		return result, compErr
	}

	return result, nil
}

// registerTaxonomyExtension registers a taxonomy extension for an agent with the taxonomy registry.
// This is called after successful agent installation to merge custom node types and relationships
// with the core taxonomy. Failures are logged as warnings but don't fail the installation.
func (i *DefaultInstaller) registerTaxonomyExtension(ctx context.Context, agentName string, manifestTaxonomy *TaxonomyExtension, span trace.Span) {
	// Skip if no taxonomy registry is configured
	if i.taxonomyRegistry == nil {
		span.AddEvent("taxonomy registry not configured, skipping extension registration", trace.WithAttributes(
			attribute.String("agent.name", agentName),
		))
		return
	}

	// Register with the taxonomy registry (manifest types are used directly)
	if err := i.taxonomyRegistry.RegisterExtension(agentName, manifestTaxonomy); err != nil {
		// Log as warning - taxonomy registration failure shouldn't fail installation
		span.AddEvent("failed to register taxonomy extension", trace.WithAttributes(
			attribute.String("agent.name", agentName),
			attribute.String("error", err.Error()),
		))
	} else {
		// Log success with counts
		span.AddEvent("registered taxonomy extension", trace.WithAttributes(
			attribute.String("agent.name", agentName),
			attribute.Int("node_types", len(manifestTaxonomy.NodeTypes)),
			attribute.Int("relationships", len(manifestTaxonomy.Relationships)),
		))
	}
}

// unregisterTaxonomyExtension removes a taxonomy extension for an agent from the taxonomy registry.
// This is called during agent uninstallation to clean up custom taxonomy definitions.
// Failures are logged but don't fail the uninstallation.
func (i *DefaultInstaller) unregisterTaxonomyExtension(ctx context.Context, agentName string, span trace.Span) {
	// Skip if no taxonomy registry is configured
	if i.taxonomyRegistry == nil {
		return
	}

	// Unregister the extension
	if err := i.taxonomyRegistry.UnregisterExtension(agentName); err != nil {
		// Log as warning - taxonomy unregistration failure shouldn't fail uninstallation
		span.AddEvent("failed to unregister taxonomy extension", trace.WithAttributes(
			attribute.String("agent.name", agentName),
			attribute.String("error", err.Error()),
		))
	} else {
		span.AddEvent("unregistered taxonomy extension", trace.WithAttributes(
			attribute.String("agent.name", agentName),
		))
	}
}

// taxonomyRegistryAdapter adapts the sdkGraphrag.TaxonomyRegistry to work with component.TaxonomyExtension types.
// This avoids circular imports and type conflicts between packages.
type taxonomyRegistryAdapter struct {
	registry sdkGraphrag.TaxonomyRegistry
}

// NewTaxonomyRegistryAdapter creates a new adapter for the sdkGraphrag TaxonomyRegistry.
func NewTaxonomyRegistryAdapter(registry sdkGraphrag.TaxonomyRegistry) TaxonomyRegistry {
	return &taxonomyRegistryAdapter{registry: registry}
}

// RegisterExtension converts component.TaxonomyExtension to sdkGraphrag.TaxonomyExtension and registers it.
func (a *taxonomyRegistryAdapter) RegisterExtension(agentName string, ext *TaxonomyExtension) error {
	if ext == nil {
		return nil
	}

	// Convert component types to graphrag types
	graphragExt := sdkGraphrag.TaxonomyExtension{
		NodeTypes:     make([]sdkGraphrag.NodeTypeDefinition, len(ext.NodeTypes)),
		Relationships: make([]sdkGraphrag.RelationshipDefinition, len(ext.Relationships)),
	}

	// Convert node types
	for i, nt := range ext.NodeTypes {
		graphragExt.NodeTypes[i] = sdkGraphrag.NodeTypeDefinition{
			Name:       nt.Name,
			Category:   nt.Category,
			Properties: make([]sdkGraphrag.PropertyInfo, len(nt.Properties)),
		}
		for j, prop := range nt.Properties {
			graphragExt.NodeTypes[i].Properties[j] = sdkGraphrag.PropertyInfo{
				Name: prop.Name,
				Type: prop.Type,
			}
		}
	}

	// Convert relationships
	for i, rel := range ext.Relationships {
		graphragExt.Relationships[i] = sdkGraphrag.RelationshipDefinition{
			Name:      rel.Name,
			FromTypes: rel.FromTypes,
			ToTypes:   rel.ToTypes,
		}
	}

	return a.registry.RegisterExtension(agentName, graphragExt)
}

// UnregisterExtension removes a taxonomy extension for an agent.
func (a *taxonomyRegistryAdapter) UnregisterExtension(agentName string) error {
	return a.registry.UnregisterExtension(agentName)
}

// SetTaxonomyRegistry sets the taxonomy registry for the installer.
// This is optional - if not set, taxonomy extension cleanup will be skipped during uninstall.
func (i *DefaultInstaller) SetTaxonomyRegistry(registry TaxonomyRegistry) {
	i.taxonomyRegistry = registry
}
