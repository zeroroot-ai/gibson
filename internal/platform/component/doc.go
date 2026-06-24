// Package component provides external component management for the Gibson Framework.
//
// # Overview
//
// The component package enables Gibson to discover, manage, and monitor
// external components (agents, tools, and plugins). It provides lifecycle
// management for registered components including starting, health monitoring,
// and graceful shutdown.
//
// # Main Interfaces
//
// The package defines two primary interfaces for component management:
//
// ## ComponentStore
//
// ComponentStore manages the registration and persistence of components in Redis:
//
//	type ComponentStore interface {
//	    Create(ctx context.Context, comp *Component) error
//	    GetByName(ctx context.Context, kind ComponentKind, name string) (*Component, error)
//	    List(ctx context.Context, kind ComponentKind) ([]*Component, error)
//	    ListAll(ctx context.Context) (map[ComponentKind][]*Component, error)
//	    Update(ctx context.Context, comp *Component) error
//	    Delete(ctx context.Context, kind ComponentKind, name string) error
//	    ListInstances(ctx context.Context, kind ComponentKind, name string) ([]ServiceInfo, error)
//	}
//
// The store is used by the LifecycleManager to persist component metadata.
// Components are organized by kind (agent, tool, plugin) and name, with unique constraints
// enforced by Redis atomic operations. Component metadata is stored persistently, while running
// instances are stored with leases (ephemeral) for automatic cleanup.
//
// ## LifecycleManager
//
// LifecycleManager controls component execution and process management:
//
//	type LifecycleManager interface {
//	    StartComponent(ctx context.Context, comp *Component) (int, error)
//	    StopComponent(ctx context.Context, comp *Component) error
//	    RestartComponent(ctx context.Context, comp *Component) (int, error)
//	    GetStatus(ctx context.Context, comp *Component) (ComponentStatus, error)
//	}
//
// The lifecycle manager starts components as processes, assigns ports, monitors
// process health, and performs graceful shutdown (SIGTERM followed by SIGKILL).
//
// # Manifest Format
//
// Components are described by a manifest file (component.yaml) that defines
// their metadata, build configuration, runtime requirements, and dependencies.
//
// Example manifest:
//
//	name: scanner
//	version: 1.0.0
//	description: Network vulnerability scanner agent
//	author: Security Team
//	license: MIT
//	repository: https://github.com/org/gibson-agent-scanner
//
// Note: Component kind is no longer stored in the manifest. Instead, it is determined
// by the installation command (e.g., 'gibson agent install' for agents). This allows
// the same component to be used in different contexts if needed.
//
//	build:
//	  command: make build
//	  artifacts:
//	    - bin/scanner
//	  workdir: .
//	  env:
//	    CGO_ENABLED: "0"
//	    GOOS: linux
//
//	runtime:
//	  type: go
//	  entrypoint: ./bin/scanner
//	  args:
//	    - --verbose
//	  env:
//	    LOG_LEVEL: info
//	  port: 50000
//	  health_url: /health
//	  workdir: /opt/scanner
//
//	dependencies:
//	  gibson: ">=1.0.0"
//	  components:
//	    - nmap-tool@2.0.0
//	  system:
//	    - docker
//	    - nmap
//	  env:
//	    SCANNER_API_KEY: required
//
// # Component Lifecycle
//
// Components follow a well-defined lifecycle from registration to removal:
//
//  1. Register: Add component to registry and persist to disk
//  2. Start: Launch component process, assign port, wait for health check
//  3. Monitor: Periodic health checks, status change notifications
//  4. Stop: Graceful shutdown (SIGTERM) with timeout, force kill (SIGKILL) if needed
//
// # Component Kinds
//
// Gibson supports three component types:
//
//   - Agent (ComponentKindAgent): Autonomous services that perform specific tasks
//   - Tool (ComponentKindTool): Utilities and external programs invoked by agents
//   - Plugin (ComponentKindPlugin): Extensions that add functionality to Gibson
//
// # Component Sources
//
// Components can originate from different sources:
//
//   - Internal (ComponentSourceInternal): Built-in components distributed with Gibson
//   - External (ComponentSourceExternal): Third-party components installed from git
//   - Remote (ComponentSourceRemote): Network services accessed via HTTP/gRPC
//   - Config (ComponentSourceConfig): Components defined in configuration files
//
// # Component Statuses
//
// Components transition through various statuses during their lifecycle:
//
//   - Available (ComponentStatusAvailable): Installed and ready to start
//   - Running (ComponentStatusRunning): Currently executing with active process
//   - Stopped (ComponentStatusStopped): Previously running, now stopped
//   - Error (ComponentStatusError): Encountered error, health check failing
//
// # Logging Subsystem
//
// The component package provides a comprehensive logging system that captures
// stdout and stderr from running components to persistent log files with automatic
// rotation to prevent disk exhaustion.
//
// ## LogWriter Interface
//
// LogWriter provides the core abstraction for capturing component output:
//
//	type LogWriter interface {
//	    CreateWriter(componentName string, stream string) (io.WriteCloser, error)
//	    Close(componentName string) error
//	}
//
// The LogWriter creates separate writers for stdout and stderr streams, automatically
// prefixing each line with timestamps and stream markers for easy parsing and debugging.
//
// ## DefaultLogWriter Implementation
//
// DefaultLogWriter is the standard implementation that writes logs to the filesystem:
//
//   - Log Location: ~/.gibson/logs/<component-name>.log (configurable)
//   - Thread Safety: Safe for concurrent writes from multiple streams
//   - Automatic Rotation: Integrates with LogRotator to prevent disk exhaustion
//   - Buffering: Uses 64KB buffers for efficient I/O
//
// ## Log Format
//
// All log entries follow a standardized format for easy parsing:
//
//	2025-01-01T12:00:00-06:00 [STDOUT] message here
//	2025-01-01T12:00:01-06:00 [STDERR] error message
//	2025-01-01T12:00:02-06:00 [SYSTEM] component started
//
// Format components:
//   - Timestamp: RFC3339 format with timezone (2006-01-02T15:04:05Z07:00)
//   - Stream Marker: [STDOUT], [STDERR], or [SYSTEM] for system messages
//   - Message: The actual log message (preserves original formatting)
//
// This format enables:
//   - Chronological sorting across streams
//   - Stream filtering (stdout vs stderr)
//   - Automated parsing by log analysis tools
//   - Human-readable debugging output
//
// ## LogRotator Interface
//
// LogRotator defines the strategy for rotating log files:
//
//	type LogRotator interface {
//	    ShouldRotate(path string) (bool, error)
//	    Rotate(path string) (*os.File, error)
//	}
//
// The rotator prevents log files from consuming excessive disk space by:
//  1. Monitoring file sizes (checks every 1MB of writes)
//  2. Rotating files when they exceed the threshold
//  3. Maintaining a configurable number of backup files
//
// ## DefaultLogRotator Implementation
//
// DefaultLogRotator implements size-based rotation with these defaults:
//
//   - Max Size: 10MB per log file (DefaultLogMaxSize)
//   - Max Backups: 5 old versions retained (DefaultLogMaxBackups)
//   - File Naming: .log, .log.1, .log.2, .log.3, .log.4, .log.5
//   - Thread Safety: Rotation operations are synchronized
//
// Rotation process:
//  1. Delete oldest backup (.log.5)
//  2. Shift existing backups (.log.1 → .log.2, .log.2 → .log.3, etc.)
//  3. Rename current .log to .log.1
//  4. Create new empty .log file
//
// The rotation is atomic where possible and handles missing files gracefully.
//
// ## Log Parser
//
// The package includes ParseRecentErrors() for extracting error information:
//
//   - Supported Formats: JSON and key=value log formats
//   - Error Levels: Filters for ERROR and FATAL entries
//   - Sorting: Returns newest errors first
//   - Resilience: Skips malformed lines without failing
//
// This enables the health monitoring system to detect component failures and
// provide diagnostic information to operators.
//
// # Configuration Options
//
// The ComponentConfig type (defined in manifest) supports various runtime options:
//
//   - Runtime Type: Execution environment (go, python, node, docker, binary, http, grpc)
//   - Entrypoint: Command or executable to run
//   - Arguments: Command-line arguments passed to the component
//   - Environment: Environment variables for the component
//   - Working Directory: Execution directory
//   - Port: Network port for HTTP/gRPC components
//   - Health URL: Endpoint for health checks
//   - Volumes: Docker volume mounts (for container runtime)
//
// # Usage Examples
//
// ## Using the Component Store
//
// Register, query, and persist components in Redis:
//
//	func useComponentStore() {
//	    store := component.NewRedisComponentStore(redisClient, "gibson")
//	    ctx := context.Background()
//
//	    // Create and register a component
//	    comp := &component.Component{
//	        Kind:      component.ComponentKindAgent,
//	        Name:      "scanner",
//	        Version:   "1.0.0",
//	        BinPath:   "/home/user/.gibson/agents/bin/scanner",
//	        Source:    component.ComponentSourceExternal,
//	        Status:    component.ComponentStatusAvailable,
//	        CreatedAt: time.Now(),
//	        UpdatedAt: time.Now(),
//	    }
//
//	    // Register the component
//	    if err := store.Create(ctx, comp); err != nil {
//	        log.Fatalf("Failed to register component: %v", err)
//	    }
//
//	    // Query components
//	    scanner, err := store.GetByName(ctx, component.ComponentKindAgent, "scanner")
//	    if err != nil {
//	        log.Fatalf("Failed to get component: %v", err)
//	    }
//	    agents, err := store.List(ctx, component.ComponentKindAgent)
//	    if err != nil {
//	        log.Fatalf("Failed to list agents: %v", err)
//	    }
//
//	    fmt.Printf("Found component: %s v%s\n", scanner.Name, scanner.Version)
//	    fmt.Printf("Total agents: %d\n", len(agents))
//
//	    // List all components
//	    allComponents, err := store.ListAll(ctx)
//	    if err != nil {
//	        log.Fatalf("Failed to list components: %v", err)
//	    }
//	    totalCount := 0
//	    for _, components := range allComponents {
//	        totalCount += len(components)
//	    }
//	    fmt.Printf("Total components: %d\n", totalCount)
//	}
//
// ## Loading and Validating Manifests
//
// Load component manifests and access their configuration:
//
//	func loadManifest() {
//	    manifestPath := "/path/to/component.yaml"
//	    manifest, err := component.LoadManifest(manifestPath)
//	    if err != nil {
//	        log.Fatalf("Failed to load manifest: %v", err)
//	    }
//
//	    // Access manifest fields
//	    fmt.Printf("Component: %s v%s\n",
//	        manifest.Name,
//	        manifest.Version)
//	    // Note: Kind is not stored in manifest, it's provided during installation
//
//	    // Check runtime configuration
//	    if manifest.Runtime.IsNetworkBased() {
//	        fmt.Printf("Network component on port %d\n", manifest.Runtime.Port)
//	    }
//
//	    // Check dependencies
//	    if manifest.Dependencies != nil && manifest.Dependencies.HasDependencies() {
//	        fmt.Printf("Dependencies:\n")
//	        fmt.Printf("  Gibson: %s\n", manifest.Dependencies.Gibson)
//	        for _, dep := range manifest.Dependencies.GetComponents() {
//	            fmt.Printf("  Component: %s\n", dep)
//	        }
//	        for _, dep := range manifest.Dependencies.GetSystem() {
//	            fmt.Printf("  System: %s\n", dep)
//	        }
//	    }
//
//	    // Access build configuration
//	    if manifest.Build != nil {
//	        fmt.Printf("Build command: %s\n", manifest.Build.Command)
//	        for _, artifact := range manifest.Build.GetBuildArtifacts() {
//	            fmt.Printf("  Artifact: %s\n", artifact)
//	        }
//	    }
//	}
//
// ## Using the Logging Subsystem
//
// Capture component output to persistent log files with rotation:
//
//	import (
//	    "os/exec"
//	    "path/filepath"
//	)
//
//	func captureComponentLogs() {
//	    // Create log writer with default rotation (10MB max, 5 backups)
//	    logDir := filepath.Join(os.Getenv("HOME"), ".gibson", "logs")
//	    rotator := component.NewDefaultLogRotator(0, 0) // Use defaults
//	    logWriter, err := component.NewDefaultLogWriter(logDir, rotator)
//	    if err != nil {
//	        log.Fatalf("Failed to create log writer: %v", err)
//	    }
//
//	    componentName := "scanner"
//
//	    // Create writers for stdout and stderr
//	    stdoutWriter, err := logWriter.CreateWriter(componentName, "stdout")
//	    if err != nil {
//	        log.Fatalf("Failed to create stdout writer: %v", err)
//	    }
//	    defer stdoutWriter.Close()
//
//	    stderrWriter, err := logWriter.CreateWriter(componentName, "stderr")
//	    if err != nil {
//	        log.Fatalf("Failed to create stderr writer: %v", err)
//	    }
//	    defer stderrWriter.Close()
//
//	    // Start component process with log capture
//	    cmd := exec.Command("./bin/scanner", "--verbose")
//	    cmd.Stdout = stdoutWriter
//	    cmd.Stderr = stderrWriter
//
//	    if err := cmd.Start(); err != nil {
//	        log.Fatalf("Failed to start component: %v", err)
//	    }
//
//	    // Component output is now being captured to:
//	    // ~/.gibson/logs/scanner.log
//	    // with automatic rotation when file exceeds 10MB
//
//	    // Wait for component to complete
//	    if err := cmd.Wait(); err != nil {
//	        log.Printf("Component exited with error: %v", err)
//	    }
//
//	    // Clean up writers
//	    if err := logWriter.Close(componentName); err != nil {
//	        log.Printf("Warning: failed to close log writers: %v", err)
//	    }
//	}
//
// ## Parsing Component Logs
//
// Extract recent errors from component logs for debugging:
//
//	func checkComponentErrors() {
//	    logPath := filepath.Join(os.Getenv("HOME"), ".gibson", "logs", "scanner.log")
//
//	    // Get the 10 most recent errors
//	    errors, err := component.ParseRecentErrors(logPath, 10)
//	    if err != nil {
//	        log.Fatalf("Failed to parse errors: %v", err)
//	    }
//
//	    if len(errors) == 0 {
//	        fmt.Println("No errors found in logs")
//	        return
//	    }
//
//	    // Display errors (sorted newest first)
//	    fmt.Printf("Found %d recent errors:\n", len(errors))
//	    for i, logErr := range errors {
//	        fmt.Printf("[%d] %s [%s] %s\n",
//	            i+1,
//	            logErr.Timestamp.Format("2006-01-02 15:04:05"),
//	            logErr.Level,
//	            logErr.Message)
//	    }
//	}
//
// ## Custom Log Rotation Configuration
//
// Configure custom rotation thresholds:
//
//	func customLogRotation() {
//	    // Rotate at 50MB, keep 10 backups
//	    maxSize := int64(50 * 1024 * 1024)  // 50MB
//	    maxBackups := 10
//	    rotator := component.NewDefaultLogRotator(maxSize, maxBackups)
//
//	    logDir := "/var/log/gibson"
//	    logWriter, err := component.NewDefaultLogWriter(logDir, rotator)
//	    if err != nil {
//	        log.Fatalf("Failed to create log writer: %v", err)
//	    }
//
//	    // Use the custom-configured writer
//	    writer, err := logWriter.CreateWriter("my-component", "stdout")
//	    if err != nil {
//	        log.Fatalf("Failed to create writer: %v", err)
//	    }
//	    defer writer.Close()
//
//	    // Logs will now rotate at 50MB and keep 10 backups:
//	    // /var/log/gibson/my-component.log
//	    // /var/log/gibson/my-component.log.1
//	    // /var/log/gibson/my-component.log.2
//	    // ... up to .log.10
//	}
//
// ## Handling Errors
//
// The package provides structured error handling with ComponentError:
//
//	func handleErrors() {
//	    store := component.NewRedisComponentStore(redisClient, "gibson")
//	    comp, err := store.GetByName(ctx, component.ComponentKindAgent, "scanner")
//
//	    if err != nil || comp == nil {
//	        // Component not found - not an error, just nil
//	        fmt.Println("Component not found")
//	        return
//	    }
//
//	    // Operations that may return ComponentError
//	    err := registry.Register(comp)
//	    if err != nil {
//	        // Check if it's a ComponentError
//	        var compErr *component.ComponentError
//	        if errors.As(err, &compErr) {
//	            // Access error details
//	            fmt.Printf("Error code: %s\n", compErr.Code)
//	            fmt.Printf("Component: %s\n", compErr.Component)
//	            fmt.Printf("Retryable: %t\n", compErr.Retryable)
//
//	            // Check error context
//	            for key, value := range compErr.Context {
//	                fmt.Printf("  %s: %v\n", key, value)
//	            }
//
//	            // Check for specific error types
//	            switch compErr.Code {
//	            case component.ErrCodeComponentExists:
//	                fmt.Println("Component already exists, use Force option")
//	            case component.ErrCodeComponentNotFound:
//	                fmt.Println("Component not found in registry")
//	            case component.ErrCodeValidationFailed:
//	                fmt.Println("Component validation failed")
//	            case component.ErrCodeTimeout:
//	                if compErr.Retryable {
//	                    fmt.Println("Operation timed out, retrying...")
//	                }
//	            }
//	        }
//	    }
//	}
//
// # Thread Safety
//
// The ComponentStore uses Redis for persistence, which provides atomic operations
// consistency through Raft consensus. Multiple processes can safely access
// the store concurrently. Redis atomic operations (SET NX, pipelines) ensure
// create-if-not-exists and delete-with-prefix patterns.
//
// # Error Handling
//
// The package uses structured errors (ComponentError) that include:
//   - Error codes for programmatic handling
//   - Human-readable messages
//   - Underlying cause errors (unwrappable)
//   - Component context information
//   - Retryable flag for transient errors
//
// All errors can be unwrapped using errors.Is() and errors.As() for proper
// error chain inspection.
//
// # Best Practices
//
//  1. Always use context.Context for cancellation and timeouts
//  2. Check ComponentError.Retryable before implementing retry logic
//  3. Validate manifests before attempting installation
//  4. Monitor component health in production environments
//  5. Implement graceful shutdown handlers for component processes
//  6. Component state is automatically persisted to Redis
//  7. Handle dependency failures gracefully
//  8. Set appropriate timeouts for install/build operations
//  9. Clean up resources on installation failures
//  10. Use structured logging with component context
//
// # Testing
//
// The package includes comprehensive test coverage including unit tests,
// integration tests, and concurrent operation tests. Mock implementations
// are provided for git operations and build execution to facilitate testing
// without external dependencies.
package component
