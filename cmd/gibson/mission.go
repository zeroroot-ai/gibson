package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/core"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	dclient "github.com/zero-day-ai/gibson/internal/daemon/client"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/mission"
	"gopkg.in/yaml.v3"
)

var missionCmd = &cobra.Command{
	Use:   "mission",
	Short: "Manage missions",
	Long:  `Manage Gibson missions - create, run, monitor, and control mission execution`,
}

var missionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all missions",
	Long: `List all missions with optional status filter.

By default, shows mission execution instances (running, paused, completed).
Use --definitions to show installed mission templates instead.`,
	RunE: runMissionList,
}

var missionShowCmd = &cobra.Command{
	Use:   "show NAME",
	Short: "Show mission details",
	Long:  `Display detailed information about a specific mission including workflow, status, and progress`,
	Args:  cobra.ExactArgs(1),
	RunE:  runMissionShow,
}

var missionRunCmd = &cobra.Command{
	Use:   "run [NAME|FILE|URL]",
	Short: "Run a new mission",
	Long: `Run a mission from an installed definition, file path, or git URL.

Auto-detection:
  - If argument contains "://" or starts with "git@" -> treated as URL (temporary clone)
  - If argument is a valid file path -> loads from file
  - Otherwise -> loads from installed mission by name

When using -f/--file flag, always loads from the specified file path.

Examples:
  gibson mission run my-recon-mission                           # Run installed mission
  gibson mission run ./workflows/scan.yaml                      # Run from file
  gibson mission run https://github.com/user/mission            # Run from URL (temporary)
  gibson mission run -f scan.yaml                               # Run from file (explicit)
  gibson mission run my-mission --target api.example.com        # Override target`,
	RunE: runMissionRun,
}

var missionResumeCmd = &cobra.Command{
	Use:   "resume <mission-id>",
	Short: "Resume a paused mission",
	Long: `Resume execution of a paused mission from its last checkpoint.

The mission will restore its state from the last saved checkpoint and continue
execution from where it left off. All previously discovered findings, metrics,
and completed workflow nodes are preserved.

CHECKPOINT SELECTION:
  By default, the latest checkpoint is used. Use --from-checkpoint to specify
  a particular checkpoint ID to resume from. This is useful if you want to
  restart from an earlier point in the mission execution.

The mission must be in 'paused' status to be resumed. Use 'gibson mission status'
to check the current status and checkpoint availability.`,
	Example: `  # Resume from the latest checkpoint
  gibson mission resume mission-20260107-153045-abc123

  # Resume from a specific checkpoint
  gibson mission resume mission-20260107-153045-abc123 --from-checkpoint chk-20260107-153100-def456

  # Check status before resuming
  gibson mission status mission-20260107-153045-abc123
  gibson mission resume mission-20260107-153045-abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionResume,
}

var missionStopCmd = &cobra.Command{
	Use:   "stop NAME",
	Short: "Stop a running mission",
	Long:  `Stop a currently running mission (can be resumed later)`,
	Args:  cobra.ExactArgs(1),
	RunE:  runMissionStop,
}

var missionDeleteCmd = &cobra.Command{
	Use:   "delete <mission-id|name>",
	Short: "Delete a mission",
	Long:  `Delete a mission and all associated data. Accepts either a mission UUID or name.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runMissionDelete,
}

var missionPauseCmd = &cobra.Command{
	Use:   "pause <mission-id>",
	Short: "Pause a running mission",
	Long: `Pause a running mission at the next clean checkpoint boundary.

GRACEFUL PAUSE (default):
  The mission will complete its current workflow node execution before pausing.
  This ensures a consistent state is saved in the checkpoint, making resume more
  reliable. The checkpoint will include:
    - Current workflow DAG state (completed/pending nodes)
    - Node results from completed nodes
    - All findings discovered so far
    - Token usage and cost metrics

FORCE PAUSE (--force):
  The mission will pause immediately without waiting for the current node to
  complete. This may result in the mission pausing at a less optimal state,
  potentially requiring the current node to be restarted on resume.

A paused mission can be resumed later with 'gibson mission resume'.`,
	Example: `  # Gracefully pause a mission (waits for current node to complete)
  gibson mission pause mission-20260107-153045-abc123

  # Force immediate pause without waiting for clean checkpoint
  gibson mission pause mission-20260107-153045-abc123 --force

  # Pause and see checkpoint ID
  gibson mission pause mission-20260107-153045-abc123
  # Output: Mission paused. Checkpoint: chk-20260107-153100-def456`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionPause,
}

var missionHistoryCmd = &cobra.Command{
	Use:   "history <name>",
	Short: "Show mission execution history",
	Long: `Display the complete execution history for a mission name.

This command shows all execution runs of missions with the given workflow name.
Each run represents a separate execution instance, allowing you to track how
a mission has been executed over time.

DISPLAYED INFORMATION:
  - Run number: Sequential execution number (1, 2, 3, ...)
  - Mission ID: Unique identifier for each run
  - Status: Current or final status (running, paused, completed, failed)
  - Created: When the run was started
  - Completed: When the run finished (if applicable)
  - Findings: Number of security findings discovered in that run

This is useful for:
  - Comparing results across multiple runs
  - Tracking mission execution patterns
  - Auditing security testing activities
  - Finding the mission ID for a specific run to resume or inspect`,
	Example: `  # Show all runs of a mission workflow
  gibson mission history api-security-scan

  # Show limited number of recent runs
  gibson mission history api-security-scan --limit 5

  # Example output:
  # Run  Mission ID                        Status     Created              Findings
  # 3    api-security-scan-20260107-1530  completed  2026-01-07 15:30:45  12
  # 2    api-security-scan-20260106-0915  completed  2026-01-06 09:15:22  8
  # 1    api-security-scan-20260105-1420  failed     2026-01-05 14:20:11  5`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionHistory,
}

var missionCheckpointsCmd = &cobra.Command{
	Use:   "checkpoints <mission-id>",
	Short: "List checkpoints for a mission",
	Long: `Display all saved checkpoints for a specific mission.

Checkpoints represent saved execution states that can be used to resume a mission
from a specific point. They are created:
  - Automatically when pausing a mission (graceful pause)
  - Periodically during long-running missions (auto-checkpoint)
  - At workflow boundaries (node completion)

CHECKPOINT CONTENTS:
  Each checkpoint includes:
    - Complete workflow DAG state
    - Results from completed nodes
    - All findings discovered up to that point
    - Token usage and cost metrics
    - Mission metadata and configuration

USE CASES:
  - View available resume points for a paused mission
  - Select a specific checkpoint to resume from
  - Audit mission execution progress over time
  - Verify checkpoint integrity before resuming`,
	Example: `  # List all checkpoints for a mission
  gibson mission checkpoints mission-20260107-153045-abc123

  # Example output:
  # Checkpoint ID               Created              Nodes      Findings
  # chk-20260107-153100-def456  2026-01-07 15:31:00  5/10       8
  # chk-20260107-153045-abc123  2026-01-07 15:30:45  3/10       5
  # chk-20260107-153030-xyz789  2026-01-07 15:30:30  1/10       2

  # Use a checkpoint to resume
  gibson mission checkpoints mission-20260107-153045-abc123
  gibson mission resume mission-20260107-153045-abc123 --from-checkpoint chk-20260107-153045-abc123`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionCheckpoints,
}

var missionStatusCmd = &cobra.Command{
	Use:   "status <mission-id>",
	Short: "Show mission status",
	Long: `Display the current status of a mission including progress, checkpoint availability, and resume capability.

This command provides a quick overview of mission state, useful for monitoring
running missions and determining if a paused mission can be resumed.`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionStatus,
}

var missionContextCmd = &cobra.Command{
	Use:   "context <mission-id>",
	Short: "Show comprehensive mission context",
	Long: `Display comprehensive context information about a mission including run history, resume status, and cross-run metrics.

This command provides a detailed view of mission execution context:
  - Mission name and ID
  - Run number (e.g., "Run 3 of 5")
  - Current status
  - Resume status (whether this run was resumed from a checkpoint)
  - Previous run details (ID and status)
  - Total findings across all runs
  - Memory continuity mode

This is useful for:
  - Understanding mission execution history
  - Tracking progress across multiple runs
  - Debugging resume/checkpoint behavior
  - Auditing security testing campaigns`,
	Example: `  # Show context for a specific mission
  gibson mission context mission-20260107-153045-abc123

  # Example output:
  # Mission Context
  # ===============
  # Name:              recon-webapp
  # Mission ID:        mission-20260107-153045-abc123
  # Run Number:        3 of 5
  # Status:            running
  # Resumed:           Yes (from checkpoint-5-nodes)
  # Previous Run:      mission-20260107-143045-xyz789 (completed)
  # Total Findings:    47 (across all runs)
  # Memory Continuity: inherit`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionContext,
}

var missionInstallCmd = &cobra.Command{
	Use:   "install URL",
	Short: "Install a mission from a git repository",
	Long: `Install a mission definition from a git repository URL.

Missions are reusable workflow templates that can be shared via git repositories.
After installation, missions can be run by name without specifying a file path.

Examples:
  gibson mission install https://github.com/user/recon-mission
  gibson mission install https://github.com/user/missions#subdirectory/advanced-scan
  gibson mission install git@github.com:user/mission.git --branch dev
  gibson mission install https://github.com/user/mission --tag v1.0.0`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionInstall,
}

var missionUninstallCmd = &cobra.Command{
	Use:   "uninstall NAME",
	Short: "Uninstall an installed mission",
	Long: `Remove an installed mission definition from the system.

This removes the mission from ~/.gibson/missions/ and the registry.
Mission execution history and findings are preserved.

Examples:
  gibson mission uninstall recon-mission
  gibson mission uninstall advanced-scan --force`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionUninstall,
}

var missionUpdateCmd = &cobra.Command{
	Use:   "update NAME",
	Short: "Update an installed mission to the latest version",
	Long: `Update an installed mission by pulling the latest version from its source repository.

The mission's git URL, branch, and tag are stored during installation and used
for updates. This command fetches the latest changes and updates the local copy.

Examples:
  gibson mission update recon-mission
  gibson mission update advanced-scan`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionUpdate,
}

var missionDefinitionShowCmd = &cobra.Command{
	Use:   "definition NAME",
	Short: "Show installed mission definition details",
	Long: `Display details about an installed mission definition.

Shows metadata including name, version, description, source URL, dependencies,
and the mission workflow structure (nodes and edges).

Use --yaml to output the raw mission.yaml file.

Examples:
  gibson mission definition recon-mission
  gibson mission definition advanced-scan --yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runMissionDefinitionShow,
}

// Flags
var (
	missionStatusFilter      string
	missionWorkflowFile      string
	missionTargetFlag        string
	missionForceDelete       bool
	missionForcePause        bool
	missionFromCheckpoint    string
	missionMemoryContinuity  string
	missionStartDependencies bool

	// Mission install/update flags
	missionInstallBranch  string
	missionInstallTag     string
	missionInstallForce   bool
	missionInstallYes     bool
	missionInstallTimeout time.Duration

	// Mission uninstall flags
	missionUninstallForce bool

	// Mission definition show flags
	missionDefinitionShowYAML bool

	// Mission list flags
	missionListDefinitions bool
	missionListJSON        bool
)

// getHomeDirFromFlags returns the Gibson home directory from flags or environment
func getHomeDirFromFlags(flags *GlobalFlags) (string, error) {
	if flags != nil && flags.HomeDir != "" {
		return flags.HomeDir, nil
	}
	return getGibsonHome()
}

// buildMissionCommandContext creates a CommandContext for mission commands.
// It handles database connection, mission store initialization, and context setup.
func buildMissionCommandContext(cmd *cobra.Command) (*core.CommandContext, error) {
	ctx := cmd.Context()

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return nil, internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Get Gibson home directory
	homeDir, err := getHomeDirFromFlags(flags)
	if err != nil {
		return nil, fmt.Errorf("failed to get Gibson home: %w", err)
	}

	// Open database
	dbPath := homeDir + "/gibson.db"
	db, err := database.Open(dbPath)
	if err != nil {
		return nil, internal.WrapError(internal.ExitDatabaseError, "failed to open database", err)
	}

	// Create mission store
	missionStore := mission.NewDBMissionStore(db)

	// Create target DAO
	targetDAO := database.NewTargetDAO(db)

	return &core.CommandContext{
		Ctx:          ctx,
		DB:           db,
		HomeDir:      homeDir,
		MissionStore: missionStore,
		TargetDAO:    targetDAO,
	}, nil
}

func init() {
	// Add subcommands
	missionCmd.AddCommand(missionListCmd)
	missionCmd.AddCommand(missionShowCmd)
	missionCmd.AddCommand(missionStatusCmd)
	missionCmd.AddCommand(missionContextCmd)
	missionCmd.AddCommand(missionRunCmd)
	missionCmd.AddCommand(missionResumeCmd)
	missionCmd.AddCommand(missionStopCmd)
	missionCmd.AddCommand(missionDeleteCmd)
	missionCmd.AddCommand(missionPauseCmd)
	missionCmd.AddCommand(missionHistoryCmd)
	missionCmd.AddCommand(missionCheckpointsCmd)
	missionCmd.AddCommand(missionInstallCmd)
	missionCmd.AddCommand(missionUninstallCmd)
	missionCmd.AddCommand(missionUpdateCmd)
	missionCmd.AddCommand(missionDefinitionShowCmd)

	// List flags
	missionListCmd.Flags().StringVar(&missionStatusFilter, "status", "", "Filter by status (pending, running, paused, completed, failed)")
	missionListCmd.Flags().BoolVar(&missionListDefinitions, "definitions", false, "List installed mission definitions instead of instances")
	missionListCmd.Flags().BoolVar(&missionListJSON, "json", false, "Output in JSON format")

	// Run flags
	missionRunCmd.Flags().StringVarP(&missionWorkflowFile, "file", "f", "", "Workflow YAML file (overrides positional argument)")
	missionRunCmd.Flags().StringVar(&missionTargetFlag, "target", "", "Target name or ID (overrides YAML target if specified)")
	missionRunCmd.Flags().StringVar(&missionMemoryContinuity, "memory-continuity", "isolated", "Memory continuity mode: isolated (default), inherit, shared")
	missionRunCmd.Flags().BoolVar(&missionStartDependencies, "start-dependencies", false, "Automatically start stopped component dependencies before running the mission")

	// Delete flags
	missionDeleteCmd.Flags().BoolVar(&missionForceDelete, "force", false, "Skip confirmation prompt")

	// Pause flags
	missionPauseCmd.Flags().BoolVar(&missionForcePause, "force", false, "Pause immediately without waiting for clean checkpoint boundary")

	// Resume flags
	missionResumeCmd.Flags().StringVar(&missionFromCheckpoint, "from-checkpoint", "", "Resume from specific checkpoint ID (optional)")

	// Install flags
	missionInstallCmd.Flags().StringVar(&missionInstallBranch, "branch", "", "Git branch to install")
	missionInstallCmd.Flags().StringVar(&missionInstallTag, "tag", "", "Git tag to install")
	missionInstallCmd.Flags().BoolVar(&missionInstallForce, "force", false, "Force reinstall if mission exists")
	missionInstallCmd.Flags().BoolVar(&missionInstallYes, "yes", false, "Auto-confirm dependency installation")
	missionInstallCmd.Flags().DurationVar(&missionInstallTimeout, "timeout", 5*time.Minute, "Installation timeout")

	// Uninstall flags
	missionUninstallCmd.Flags().BoolVar(&missionUninstallForce, "force", false, "Skip confirmation prompt")

	// Definition show flags
	missionDefinitionShowCmd.Flags().BoolVar(&missionDefinitionShowYAML, "yaml", false, "Output raw YAML")
}

// runMissionList lists all missions with optional status filter
func runMissionList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// If --definitions flag is set, list installed mission definitions
	if missionListDefinitions {
		return runMissionListDefinitions(cmd, args)
	}

	// Otherwise, list mission execution instances (existing behavior)
	// Try daemon first (optional - fall back to local if unavailable)
	client := dclient.OptionalDaemon(ctx)
	if client != nil {
		defer client.Close()

		// Query missions from daemon
		missions, total, err := client.ListMissions(ctx, false, missionStatusFilter, "", 100, 0)
		if err == nil {
			// Display missions from daemon
			fmt.Printf("Found %d missions (from daemon)\n\n", total)
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tWORKFLOW\tSTARTED\tFINDINGS")
			for _, m := range missions {
				var startTime string
				if m.StartTime.IsZero() {
					startTime = "-"
				} else {
					startTime = m.StartTime.Format("2006-01-02 15:04")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n",
					m.ID, m.Status, m.WorkflowPath, startTime, m.FindingCount)
			}
			w.Flush()
			return nil
		}
	}

	// Fall back to local data
	fmt.Fprintln(os.Stderr, "[WARN] Daemon not running, showing local data only")

	// Build command context for local query
	cc, err := buildMissionCommandContext(cmd)
	if err != nil {
		return err
	}
	defer internal.CloseWithLog(cc, nil, "gRPC connection")

	// Call core function
	result, err := core.MissionList(cc, missionStatusFilter)
	if err != nil {
		return err
	}

	// Handle errors from core
	if result.Error != nil {
		return internal.WrapError(internal.ExitError, "mission list failed", result.Error)
	}

	// Format output
	return formatMissionListOutput(cmd, result)
}

// runMissionListDefinitions lists installed mission definitions
func runMissionListDefinitions(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Listing definitions requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission definition listing requires daemon", err)
	}
	defer client.Close()

	// Get mission definitions via daemon
	definitions, err := client.ListMissionDefinitions(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to list mission definitions", err)
	}

	// If --json flag is set, output JSON
	if missionListJSON {
		data, err := json.MarshalIndent(definitions, "", "  ")
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to marshal JSON", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Display formatted output
	if len(definitions) == 0 {
		fmt.Println("No installed mission definitions found")
		fmt.Println("\nInstall missions with: gibson mission install <url>")
		return nil
	}

	fmt.Printf("Found %d installed mission definition(s)\n\n", len(definitions))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tDESCRIPTION")

	for _, def := range definitions {
		// Truncate description if too long
		desc := def.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", def.Name, def.Version, desc)
	}

	w.Flush()
	return nil
}

// runMissionShow shows detailed mission information
func runMissionShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionName := args[0]

	// Try daemon first (optional - fall back to local if unavailable)
	client := dclient.OptionalDaemon(ctx)
	if client != nil {
		defer client.Close()

		// Query mission from daemon using name pattern filter
		missions, _, err := client.ListMissions(ctx, false, "", missionName, 10, 0)
		if err == nil && len(missions) > 0 {
			// Find exact match by ID or workflow path containing the name
			for _, m := range missions {
				if strings.Contains(m.ID, missionName) || strings.Contains(m.WorkflowPath, missionName) {
					// Display mission details from daemon
					fmt.Printf("Mission: %s\n", m.ID)
					fmt.Printf("Status: %s\n", m.Status)
					fmt.Printf("Workflow: %s\n", m.WorkflowPath)
					fmt.Printf("Started: %s\n", m.StartTime.Format("2006-01-02 15:04:05"))
					if !m.EndTime.IsZero() {
						fmt.Printf("Ended: %s\n", m.EndTime.Format("2006-01-02 15:04:05"))
					}
					fmt.Printf("Findings: %d\n", m.FindingCount)
					return nil
				}
			}
		}
	}

	// Fall back to local data
	fmt.Fprintln(os.Stderr, "[WARN] Daemon not running, showing local data only")

	// Build command context for local query
	cc, err := buildMissionCommandContext(cmd)
	if err != nil {
		return err
	}
	defer internal.CloseWithLog(cc, nil, "gRPC connection")

	// Call core function
	result, err := core.MissionShow(cc, missionName)
	if err != nil {
		return err
	}

	// Handle errors from core
	if result.Error != nil {
		return internal.WrapError(internal.ExitError, "mission show failed", result.Error)
	}

	// Format output
	return formatMissionShowOutput(cmd, result)
}

// runMissionRun creates and runs a new mission from workflow YAML
func runMissionRun(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse global flags for verbose logging
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Validate memory continuity flag
	switch missionMemoryContinuity {
	case "isolated", "inherit", "shared", "":
		// valid
	default:
		return internal.WrapError(internal.ExitConfigError,
			fmt.Sprintf("invalid memory-continuity: %s (must be isolated, inherit, or shared)", missionMemoryContinuity), nil)
	}

	// Setup verbose logging infrastructure
	jsonOutput := flags.OutputFormat == "json"
	cleanup := internal.SetupVerbose(cmd, flags.VerbosityLevel(), jsonOutput)
	defer cleanup()

	verbose := flags.IsVerbose()

	// Determine the source: file flag, positional argument, or error
	var source string
	var sourceType string // "file", "url", or "name"

	if missionWorkflowFile != "" {
		// -f/--file flag takes precedence
		source = missionWorkflowFile
		sourceType = "file"
	} else if len(args) > 0 {
		// Use positional argument and auto-detect type
		source = args[0]
		sourceType = detectMissionSourceType(source)
	} else {
		return internal.WrapError(internal.ExitConfigError,
			"mission source required: provide a mission name, file path, or use -f flag", nil)
	}

	// Verbose output
	if verbose {
		switch sourceType {
		case "url":
			fmt.Printf("Loading mission from URL: %s\n", source)
		case "file":
			fmt.Printf("Loading mission from file: %s\n", source)
		case "name":
			fmt.Printf("Loading installed mission: %s\n", source)
		}
		if missionMemoryContinuity != "" && missionMemoryContinuity != "isolated" {
			fmt.Printf("Memory continuity: %s\n", missionMemoryContinuity)
		}
	}

	// Mission execution requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission execution requires daemon", err)
	}
	defer client.Close()

	// For URL and name sources, we need to resolve to a file path first
	// This will be handled by the daemon when we add RunMissionFromSource method
	// For now, we'll continue using the file-based approach
	if sourceType != "file" {
		return internal.WrapError(internal.ExitError,
			fmt.Sprintf("mission source type '%s' not yet fully implemented (use file path with -f flag for now)", sourceType), nil)
	}

	// Check dependencies before starting the mission
	if err := checkAndStartDependencies(ctx, client, source, verbose); err != nil {
		return internal.WrapError(internal.ExitError, "dependency check failed", err)
	}

	// Extract mission name from workflow to check for paused missions
	missionName := getMissionNameFromWorkflow(source)

	// Check for paused missions with this name and auto-resume
	if missionName != "" {
		pausedMissions, _, err := client.ListMissions(ctx, true, "paused", missionName, 1, 0)
		if err == nil && len(pausedMissions) > 0 {
			m := pausedMissions[0]
			if verbose {
				fmt.Printf("Found paused mission %s, auto-resuming...\n", m.ID)
			} else {
				fmt.Printf("Resuming paused mission %s...\n", m.ID)
			}

			// Auto-resume the paused mission
			eventChan, err := client.ResumeMission(ctx, m.ID, "")
			if err != nil {
				// If resume fails (e.g., no checkpoint), cancel the orphaned mission and start fresh
				fmt.Fprintf(os.Stderr, "Warning: Cannot resume paused mission %s: %v\n", m.ID, err)
				fmt.Fprintf(os.Stderr, "Cancelling orphaned mission and starting fresh...\n")

				// Try to stop/cancel the paused mission to clean up
				if stopErr := client.StopMission(ctx, m.ID, true); stopErr != nil {
					if verbose {
						fmt.Fprintf(os.Stderr, "Note: Could not cancel orphaned mission: %v\n", stopErr)
					}
				}
				// Fall through to start a new mission
			} else {
				// Stream resumed mission events
				return streamMissionEvents(cmd, eventChan, m.ID, verbose)
			}
		}
	}

	// If target flag is provided, inject it into the workflow YAML
	workflowSource := source
	if missionTargetFlag != "" {
		if verbose {
			fmt.Printf("Injecting target: %s\n", missionTargetFlag)
		}
		// Create a temporary file with the target injected
		injectedPath, err := injectTargetIntoWorkflow(source, missionTargetFlag)
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to inject target into workflow", err)
		}
		defer os.Remove(injectedPath) // Clean up temp file
		workflowSource = injectedPath
	}

	// Start mission execution via daemon
	eventChan, err := client.RunMission(ctx, workflowSource, missionMemoryContinuity)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to start mission", err)
	}

	// Stream and display events
	return streamMissionEvents(cmd, eventChan, "", verbose)
}

// streamMissionEvents handles streaming mission events to the console.
// If initialMissionID is provided, it's used instead of extracting from mission.started event.
func streamMissionEvents(cmd *cobra.Command, eventChan <-chan dclient.MissionEvent, initialMissionID string, verbose bool) error {
	missionID := initialMissionID

	for event := range eventChan {
		switch event.Type {
		case "mission.started":
			if missionID == "" {
				missionID = getEventData(event.Data, "mission_id")
			}
			fmt.Printf("Mission %s started\n", missionID)

		case "mission.resumed":
			if missionID == "" {
				missionID = getEventData(event.Data, "mission_id")
			}
			fmt.Printf("Mission %s resumed\n", missionID)

		case "node.started":
			if verbose {
				nodeID := getEventData(event.Data, "node_id")
				fmt.Printf("  [%s] Node %s started\n", event.Timestamp.Format("15:04:05"), nodeID)
			}

		case "node.completed":
			if verbose {
				nodeID := getEventData(event.Data, "node_id")
				fmt.Printf("  [%s] Node %s completed\n", event.Timestamp.Format("15:04:05"), nodeID)
			}

		case "mission.completed":
			fmt.Printf("Mission %s completed successfully\n", missionID)

		case "mission.failed":
			errorMsg := event.Message
			if errorMsg == "" {
				errorMsg = getEventData(event.Data, "error")
			}
			fmt.Printf("Mission %s failed: %s\n", missionID, errorMsg)
			return internal.WrapError(internal.ExitError, "mission failed", fmt.Errorf("%s", errorMsg))

		default:
			if verbose {
				fmt.Printf("  [%s] %s: %s\n", event.Timestamp.Format("15:04:05"), event.Type, event.Message)
			}
		}
	}

	return nil
}

// getMissionNameFromWorkflow parses a workflow file and extracts the mission name.
// Returns empty string if parsing fails.
func getMissionNameFromWorkflow(workflowPath string) string {
	def, err := mission.ParseDefinition(workflowPath)
	if err != nil {
		return ""
	}
	return def.Name
}

// injectTargetIntoWorkflow reads a workflow YAML file, sets/overrides the target field,
// and writes to a temporary file. Returns the path to the temporary file.
func injectTargetIntoWorkflow(workflowPath, target string) (string, error) {
	// Read the original workflow
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		return "", fmt.Errorf("failed to read workflow file: %w", err)
	}

	// Parse as YAML to inject target
	var workflow map[string]interface{}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return "", fmt.Errorf("failed to parse workflow YAML: %w", err)
	}

	// Set/override the target field
	workflow["target"] = target

	// Marshal back to YAML
	modifiedContent, err := yaml.Marshal(workflow)
	if err != nil {
		return "", fmt.Errorf("failed to marshal modified workflow: %w", err)
	}

	// Write to a temporary file
	tmpFile, err := os.CreateTemp("", "gibson-mission-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(modifiedContent); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}

	return tmpFile.Name(), nil
}

// detectMissionSourceType determines if a source string is a URL, file path, or mission name
func detectMissionSourceType(source string) string {
	// Check if it's a URL (contains :// or starts with git@)
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git@") {
		return "url"
	}

	// Check if it's a valid file path
	if _, err := os.Stat(source); err == nil {
		return "file"
	}

	// Check common file path patterns
	if strings.Contains(source, "/") || strings.Contains(source, "\\") ||
		strings.HasSuffix(source, ".yaml") || strings.HasSuffix(source, ".yml") {
		return "file"
	}

	// Otherwise, assume it's an installed mission name
	return "name"
}

// getEventData extracts a string value from event data map
func getEventData(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// runMissionResume resumes a paused mission
func runMissionResume(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionID := args[0]

	// Parse global flags for verbose logging
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Setup verbose logging infrastructure
	jsonOutput := flags.OutputFormat == "json"
	cleanup := internal.SetupVerbose(cmd, flags.VerbosityLevel(), jsonOutput)
	defer cleanup()

	verbose := flags.IsVerbose()

	// Resuming a mission requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission resume requires daemon", err)
	}
	defer client.Close()

	// Resume the mission via daemon with optional checkpoint
	if verbose && missionFromCheckpoint != "" {
		fmt.Printf("Resuming mission %s from checkpoint %s\n", missionID, missionFromCheckpoint)
	} else if verbose {
		fmt.Printf("Resuming mission %s from last checkpoint\n", missionID)
	}

	eventChan, err := client.ResumeMission(ctx, missionID, missionFromCheckpoint)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to resume mission", err)
	}

	// Stream and display events as they occur
	nodeEvents := 0
	for event := range eventChan {
		switch event.Type {
		case "mission.resumed":
			fmt.Printf("Mission %s resumed\n", missionID)

		case "node.started":
			nodeEvents++
			if verbose {
				nodeID := getEventData(event.Data, "node_id")
				fmt.Printf("  [%s] Node %s started\n", event.Timestamp.Format("15:04:05"), nodeID)
			}

		case "node.completed":
			if verbose {
				nodeID := getEventData(event.Data, "node_id")
				fmt.Printf("  [%s] Node %s completed\n", event.Timestamp.Format("15:04:05"), nodeID)
			}

		case "mission.completed":
			fmt.Printf("Mission %s completed successfully\n", missionID)

		case "mission.failed":
			errorMsg := event.Message
			if errorMsg == "" {
				errorMsg = getEventData(event.Data, "error")
			}
			fmt.Printf("Mission %s failed: %s\n", missionID, errorMsg)
			return internal.WrapError(internal.ExitError, "mission failed", fmt.Errorf("%s", errorMsg))

		default:
			if verbose {
				fmt.Printf("  [%s] %s: %s\n", event.Timestamp.Format("15:04:05"), event.Type, event.Message)
			}
		}
	}

	return nil
}

// runMissionStop stops a running mission
func runMissionStop(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionName := args[0]

	// Stopping a mission requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission stop requires daemon", err)
	}
	defer client.Close()

	// First, find the mission ID from the name or ID
	// Try activeOnly=true first to find running/paused missions
	missions, _, err := client.ListMissions(ctx, true, "", "", 100, 0)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to query missions", err)
	}

	// Find matching mission by ID, Name, or WorkflowPath
	var missionID string
	for _, m := range missions {
		if strings.Contains(m.ID, missionName) || strings.Contains(m.Name, missionName) || strings.Contains(m.WorkflowPath, missionName) {
			missionID = m.ID
			break
		}
	}

	if missionID == "" {
		return internal.WrapError(internal.ExitError, "mission not found or not running", fmt.Errorf("no running mission matches '%s'", missionName))
	}

	// Stop the mission via daemon
	force := false // Could add a --force flag in the future
	err = client.StopMission(ctx, missionID, force)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to stop mission", err)
	}

	fmt.Printf("Mission %s stopped successfully\n", missionID)
	return nil
}

// runMissionDelete deletes a mission by ID or name
func runMissionDelete(cmd *cobra.Command, args []string) error {
	identifier := args[0]

	// Confirmation prompt unless --force is set
	if !missionForceDelete {
		fmt.Printf("Are you sure you want to delete mission '%s'? This action cannot be undone.\n", identifier)
		fmt.Print("Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Deletion cancelled")
			return nil
		}
	}

	// Build command context
	cc, err := buildMissionCommandContext(cmd)
	if err != nil {
		return err
	}
	defer internal.CloseWithLog(cc, nil, "gRPC connection")

	// Call core function
	result, err := core.MissionDelete(cc, identifier, missionForceDelete)
	if err != nil {
		return err
	}

	// Handle errors from core
	if result.Error != nil {
		return internal.WrapError(internal.ExitError, "mission delete failed", result.Error)
	}

	// Format output
	return formatMissionActionOutput(cmd, result)
}

// runMissionPause pauses a running mission
func runMissionPause(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionID := args[0]

	// Pausing a mission requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission pause requires daemon", err)
	}
	defer client.Close()

	// Pause the mission via daemon
	checkpointID, err := client.PauseMission(ctx, missionID, missionForcePause)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to pause mission", err)
	}

	// Display success message
	if missionForcePause {
		fmt.Printf("Mission %s paused immediately\n", missionID)
	} else {
		fmt.Printf("Mission %s paused gracefully\n", missionID)
	}
	if checkpointID != "" {
		fmt.Printf("Checkpoint: %s\n", checkpointID)
	}

	return nil
}

// runMissionHistory shows execution history for a mission name
func runMissionHistory(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionName := args[0]

	// Querying history requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission history requires daemon", err)
	}
	defer client.Close()

	// Get mission history from daemon
	runs, total, err := client.GetMissionHistory(ctx, missionName, 100, 0)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to get mission history", err)
	}

	// Display results
	if total == 0 {
		fmt.Printf("No execution history found for mission '%s'\n", missionName)
		return nil
	}

	fmt.Printf("Mission '%s' execution history (%d runs)\n\n", missionName, total)

	// Create table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN#\tMISSION ID\tSTATUS\tCREATED\tCOMPLETED\tFINDINGS")

	for _, run := range runs {
		createdStr := run.CreatedAt.Format("2006-01-02 15:04")
		completedStr := "-"
		if run.CompletedAt != nil {
			completedStr = run.CompletedAt.Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\n",
			run.RunNumber, run.MissionID, run.Status,
			createdStr, completedStr, run.FindingsCount)
	}

	w.Flush()
	return nil
}

// runMissionCheckpoints lists checkpoints for a mission
func runMissionCheckpoints(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionID := args[0]

	// Querying checkpoints requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission checkpoints requires daemon", err)
	}
	defer client.Close()

	// Get checkpoints from daemon
	checkpoints, err := client.GetMissionCheckpoints(ctx, missionID)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to get mission checkpoints", err)
	}

	// Display results
	if len(checkpoints) == 0 {
		fmt.Printf("No checkpoints found for mission '%s'\n", missionID)
		return nil
	}

	fmt.Printf("Checkpoints for mission '%s' (%d total)\n\n", missionID, len(checkpoints))

	// Create table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHECKPOINT ID\tCREATED\tCOMPLETED NODES\tTOTAL NODES\tFINDINGS")

	for _, cp := range checkpoints {
		createdStr := cp.CreatedAt.Format("2006-01-02 15:04:05")
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\n",
			cp.CheckpointID, createdStr, cp.CompletedNodes,
			cp.TotalNodes, cp.FindingsCount)
	}

	w.Flush()
	return nil
}

// runMissionStatus displays mission status with checkpoint information
func runMissionStatus(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	missionID := args[0]

	// Querying status requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission status requires daemon", err)
	}
	defer client.Close()

	// Query mission details from daemon
	missions, _, err := client.ListMissions(ctx, false, "", missionID, 10, 0)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to query mission", err)
	}

	// Find the matching mission
	var mission *dclient.MissionInfo
	for _, m := range missions {
		if m.ID == missionID || strings.Contains(m.ID, missionID) {
			mission = &m
			break
		}
	}

	if mission == nil {
		return internal.WrapError(internal.ExitError, "mission not found", fmt.Errorf("no mission matches '%s'", missionID))
	}

	// Query checkpoints for this mission
	checkpoints, err := client.GetMissionCheckpoints(ctx, mission.ID)
	hasCheckpoint := err == nil && len(checkpoints) > 0

	// Determine if mission can be resumed
	canResume := mission.Status == "paused" && hasCheckpoint

	// Display mission status
	fmt.Printf("Mission: %s\n", mission.ID)
	fmt.Printf("Status: %s\n", mission.Status)
	fmt.Printf("Workflow: %s\n", mission.WorkflowPath)
	fmt.Printf("Progress: %d findings\n", mission.FindingCount)

	// Time information
	fmt.Printf("Started: %s\n", mission.StartTime.Format("2006-01-02 15:04:05"))
	if !mission.EndTime.IsZero() {
		fmt.Printf("Ended: %s\n", mission.EndTime.Format("2006-01-02 15:04:05"))
	}

	// Checkpoint information
	if hasCheckpoint {
		lastCheckpoint := checkpoints[0] // Checkpoints are sorted by creation time descending
		fmt.Printf("\nCheckpoint Available: Yes\n")
		fmt.Printf("Last Checkpoint: %s\n", lastCheckpoint.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Checkpoint Progress: %d/%d nodes completed\n",
			lastCheckpoint.CompletedNodes, lastCheckpoint.TotalNodes)
	} else {
		fmt.Printf("\nCheckpoint Available: No\n")
	}

	// Resume capability
	if canResume {
		fmt.Printf("Can Resume: Yes\n")
		fmt.Printf("\nTo resume: gibson mission resume %s\n", mission.ID)
	} else if mission.Status == "paused" {
		fmt.Printf("Can Resume: No (no checkpoint available)\n")
	} else if mission.Status == "running" {
		fmt.Printf("Can Resume: N/A (mission is running)\n")
	} else {
		fmt.Printf("Can Resume: No (mission is %s)\n", mission.Status)
	}

	return nil
}

// runMissionContext displays comprehensive context for a mission
func runMissionContext(cmd *cobra.Command, args []string) error {
	missionID := args[0]

	// Build command context
	cc, err := buildMissionCommandContext(cmd)
	if err != nil {
		return err
	}
	defer internal.CloseWithLog(cc, nil, "gRPC connection")

	// Call core function
	result, err := core.MissionContext(cc, missionID)
	if err != nil {
		return err
	}

	// Handle errors from core
	if result.Error != nil {
		return internal.WrapError(internal.ExitError, "mission context failed", result.Error)
	}

	// Format output
	return formatMissionContextOutput(cmd, result)
}

// Output formatting functions

// formatMissionListOutput formats the mission list result
func formatMissionListOutput(cmd *cobra.Command, result *core.CommandResult) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	// Extract result data
	listResult, ok := result.Data.(*core.MissionListResult)
	if !ok {
		return fmt.Errorf("invalid result type for mission list")
	}

	if outFormat == internal.FormatJSON {
		return formatter.PrintJSON(map[string]interface{}{
			"missions": listResult.Missions,
			"count":    listResult.Count,
		})
	}

	// Text format
	if len(listResult.Missions) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No missions found")
		return nil
	}

	// Print table
	headers := []string{"Name", "Status", "Progress", "Findings", "Created", "Updated"}
	rows := make([][]string, 0, len(listResult.Missions))

	for _, m := range listResult.Missions {
		progressPct := fmt.Sprintf("%.1f%%", m.Progress*100)

		rows = append(rows, []string{
			m.Name,
			string(m.Status),
			progressPct,
			fmt.Sprintf("%d", m.FindingsCount),
			formatTime(m.CreatedAt),
			formatTime(m.UpdatedAt),
		})
	}

	return formatter.PrintTable(headers, rows)
}

// formatMissionShowOutput formats the mission show result
func formatMissionShowOutput(cmd *cobra.Command, result *core.CommandResult) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	// Extract mission data
	m, ok := result.Data.(*mission.Mission)
	if !ok {
		return fmt.Errorf("invalid result type for mission show")
	}

	if outFormat == internal.FormatJSON {
		return formatter.PrintJSON(m)
	}

	// Text format - detailed view
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "NAME:\t%s\n", m.Name)
	fmt.Fprintf(tw, "ID:\t%s\n", m.ID)
	fmt.Fprintf(tw, "STATUS:\t%s\n", m.Status)
	fmt.Fprintf(tw, "DESCRIPTION:\t%s\n", m.Description)
	fmt.Fprintf(tw, "PROGRESS:\t%.1f%%\n", m.Progress*100)
	fmt.Fprintf(tw, "FINDINGS:\t%d\n", m.FindingsCount)
	fmt.Fprintf(tw, "CREATED:\t%s\n", m.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "UPDATED:\t%s\n", m.UpdatedAt.Format(time.RFC3339))

	if m.StartedAt != nil {
		fmt.Fprintf(tw, "STARTED:\t%s\n", m.StartedAt.Format(time.RFC3339))
	}
	if m.CompletedAt != nil {
		fmt.Fprintf(tw, "COMPLETED:\t%s\n", m.CompletedAt.Format(time.RFC3339))
	}

	// Show workflow details
	if m.WorkflowJSON != "" {
		var def mission.MissionDefinition
		if err := json.Unmarshal([]byte(m.WorkflowJSON), &def); err == nil {
			fmt.Fprintln(tw, "")
			fmt.Fprintf(tw, "WORKFLOW:\t%s\n", def.Name)
			fmt.Fprintf(tw, "WORKFLOW ID:\t%s\n", m.WorkflowID)
			fmt.Fprintf(tw, "NODES:\t%d\n", len(def.Nodes))
			fmt.Fprintf(tw, "ENTRY POINTS:\t%d\n", len(def.EntryPoints))
			fmt.Fprintf(tw, "EXIT POINTS:\t%d\n", len(def.ExitPoints))
		}
	}

	// Show agent assignments
	if len(m.AgentAssignments) > 0 {
		fmt.Fprintln(tw, "")
		fmt.Fprintln(tw, "AGENT ASSIGNMENTS:")
		for nodeID, agentName := range m.AgentAssignments {
			fmt.Fprintf(tw, "  %s:\t%s\n", nodeID, agentName)
		}
	}

	return nil
}

// formatMissionRunOutput formats the mission run result
func formatMissionRunOutput(cmd *cobra.Command, result *core.CommandResult) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	// Extract result data
	runResult, ok := result.Data.(*core.MissionRunResult)
	if !ok {
		return fmt.Errorf("invalid result type for mission run")
	}

	if outFormat == internal.FormatJSON {
		return formatter.PrintJSON(map[string]interface{}{
			"mission": runResult.Mission,
			"status":  runResult.Status,
		})
	}

	// Print success message
	fmt.Printf("Mission '%s' started successfully\n", runResult.Mission.Name)
	fmt.Printf("Mission ID: %s\n", runResult.Mission.ID)
	fmt.Printf("Definition: %s (%d nodes)\n", runResult.Definition.Name, runResult.NodesCount)

	return nil
}

// formatMissionActionOutput formats the output for mission actions (resume, stop, delete)
func formatMissionActionOutput(cmd *cobra.Command, result *core.CommandResult) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	if outFormat == internal.FormatJSON {
		return formatter.PrintJSON(result.Data)
	}

	// Print success message
	fmt.Println(result.Message)
	return nil
}

// formatMissionContextOutput formats the mission context result
func formatMissionContextOutput(cmd *cobra.Command, result *core.CommandResult) error {
	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return internal.WrapError(internal.ExitConfigError, "failed to parse flags", err)
	}

	// Extract result data
	contextResult, ok := result.Data.(*core.MissionContextResult)
	if !ok {
		return fmt.Errorf("invalid result type for mission context")
	}

	// Create formatter
	outFormat := internal.FormatText
	if flags.OutputFormat == "json" {
		outFormat = internal.FormatJSON
	}
	formatter := internal.NewFormatter(outFormat, cmd.OutOrStdout())

	if outFormat == internal.FormatJSON {
		return formatter.PrintJSON(contextResult)
	}

	// Text format - structured display
	fmt.Fprintln(cmd.OutOrStdout(), "Mission Context")
	fmt.Fprintln(cmd.OutOrStdout(), "===============")

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "Name:\t%s\n", contextResult.MissionName)
	fmt.Fprintf(tw, "Mission ID:\t%s\n", contextResult.MissionID)
	fmt.Fprintf(tw, "Run Number:\t%d of %d\n", contextResult.RunNumber, contextResult.TotalRuns)
	fmt.Fprintf(tw, "Status:\t%s\n", contextResult.Status)

	// Resume status
	if contextResult.Resumed {
		resumeInfo := "Yes"
		if contextResult.ResumedFromNode != "" {
			resumeInfo = fmt.Sprintf("Yes (from %s)", contextResult.ResumedFromNode)
		}
		fmt.Fprintf(tw, "Resumed:\t%s\n", resumeInfo)
	} else {
		fmt.Fprintf(tw, "Resumed:\tNo\n")
	}

	// Previous run
	if contextResult.PreviousRunID != "" {
		previousInfo := contextResult.PreviousRunID
		if contextResult.PreviousStatus != "" {
			previousInfo = fmt.Sprintf("%s (%s)", contextResult.PreviousRunID, contextResult.PreviousStatus)
		}
		fmt.Fprintf(tw, "Previous Run:\t%s\n", previousInfo)
	} else {
		fmt.Fprintf(tw, "Previous Run:\tNone (first run)\n")
	}

	// Total findings
	fmt.Fprintf(tw, "Total Findings:\t%d (across all runs)\n", contextResult.TotalFindings)

	// Memory continuity
	fmt.Fprintf(tw, "Memory Continuity:\t%s\n", contextResult.MemoryContinuity)

	return nil
}

// Helper functions

func formatTime(t time.Time) string {
	// Format relative time for recent dates
	now := time.Now()
	diff := now.Sub(t)

	if diff < time.Minute {
		return "just now"
	}
	if diff < time.Hour {
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	if diff < 7*24*time.Hour {
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}

	// For older dates, show absolute date
	return t.Format("2006-01-02")
}

// runMissionInstall installs a mission from a git repository
func runMissionInstall(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	url := args[0]

	fmt.Printf("Installing mission from %s...\n", url)

	// Mission installation requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission installation requires daemon", err)
	}
	defer client.Close()

	// Build install options
	opts := dclient.MissionInstallOptions{
		Branch:  missionInstallBranch,
		Tag:     missionInstallTag,
		Force:   missionInstallForce,
		Yes:     missionInstallYes,
		Timeout: missionInstallTimeout,
	}

	// Install mission via daemon
	result, err := client.InstallMission(ctx, url, opts)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to install mission", err)
	}

	// Display success message
	fmt.Printf("Mission '%s' installed successfully (v%s) in %v\n",
		result.Name, result.Version, result.Duration)

	// Display installed dependencies if any
	if len(result.Dependencies) > 0 {
		fmt.Printf("\nInstalled dependencies:\n")
		for _, dep := range result.Dependencies {
			status := "installed"
			if dep.AlreadyInstalled {
				status = "already installed"
			}
			fmt.Printf("  - %s (%s): %s\n", dep.Name, dep.Type, status)
		}
	}

	return nil
}

// runMissionUninstall uninstalls an installed mission
func runMissionUninstall(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	name := args[0]

	// Confirmation prompt unless --force is set
	if !missionUninstallForce {
		fmt.Printf("Are you sure you want to uninstall mission '%s'?\n", name)
		fmt.Print("Type 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Uninstall cancelled")
			return nil
		}
	}

	// Mission uninstallation requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission uninstallation requires daemon", err)
	}
	defer client.Close()

	// Uninstall mission via daemon
	if err := client.UninstallMission(ctx, name, missionUninstallForce); err != nil {
		return internal.WrapError(internal.ExitError, "failed to uninstall mission", err)
	}

	fmt.Printf("Mission '%s' uninstalled successfully\n", name)
	return nil
}

// runMissionUpdate updates an installed mission
func runMissionUpdate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	name := args[0]

	fmt.Printf("Updating mission '%s'...\n", name)

	// Mission update requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission update requires daemon", err)
	}
	defer client.Close()

	// Update mission via daemon
	result, err := client.UpdateMission(ctx, name, dclient.MissionUpdateOptions{})
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to update mission", err)
	}

	// Display result
	if !result.Updated {
		fmt.Printf("Mission '%s' is already up to date (v%s)\n", name, result.OldVersion)
	} else {
		fmt.Printf("Mission '%s' updated successfully in %v\n", name, result.Duration)
		fmt.Printf("Version: %s -> %s\n", result.OldVersion, result.NewVersion)
	}

	return nil
}

// runMissionDefinitionShow displays details about an installed mission definition
func runMissionDefinitionShow(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	name := args[0]

	// Query definition requires daemon
	client, err := dclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "mission definition query requires daemon", err)
	}
	defer client.Close()

	// Get mission definition via daemon
	definition, err := client.GetMissionDefinition(ctx, name)
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to get mission definition", err)
	}

	// If --yaml flag is set, output raw YAML
	if missionDefinitionShowYAML {
		// Read the raw YAML file from the mission directory
		homeDir, err := getGibsonHome()
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to get Gibson home", err)
		}

		yamlPath := filepath.Join(homeDir, "missions", name, "mission.yaml")
		yamlData, err := os.ReadFile(yamlPath)
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read mission.yaml", err)
		}

		fmt.Println(string(yamlData))
		return nil
	}

	// Display formatted output
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "NAME:\t%s\n", definition.Name)
	fmt.Fprintf(tw, "VERSION:\t%s\n", definition.Version)
	fmt.Fprintf(tw, "DESCRIPTION:\t%s\n", definition.Description)
	fmt.Fprintf(tw, "SOURCE:\t%s\n", definition.Source)
	fmt.Fprintf(tw, "INSTALLED:\t%s\n", definition.InstalledAt.Format("2006-01-02 15:04:05"))

	// Show dependencies if present
	if definition.Dependencies != nil {
		if len(definition.Dependencies.Agents) > 0 {
			fmt.Fprintln(tw, "")
			fmt.Fprintln(tw, "REQUIRED AGENTS:")
			for _, agent := range definition.Dependencies.Agents {
				fmt.Fprintf(tw, "  - %s\n", agent)
			}
		}
		if len(definition.Dependencies.Tools) > 0 {
			fmt.Fprintln(tw, "")
			fmt.Fprintln(tw, "REQUIRED TOOLS:")
			for _, tool := range definition.Dependencies.Tools {
				fmt.Fprintf(tw, "  - %s\n", tool)
			}
		}
		if len(definition.Dependencies.Plugins) > 0 {
			fmt.Fprintln(tw, "")
			fmt.Fprintln(tw, "REQUIRED PLUGINS:")
			for _, plugin := range definition.Dependencies.Plugins {
				fmt.Fprintf(tw, "  - %s\n", plugin)
			}
		}
	}

	// Show mission structure
	fmt.Fprintln(tw, "")
	fmt.Fprintf(tw, "NODES:\t%d\n", len(definition.Nodes))
	fmt.Fprintf(tw, "EDGES:\t%d\n", len(definition.Edges))
	fmt.Fprintf(tw, "ENTRY POINTS:\t%d\n", len(definition.EntryPoints))
	fmt.Fprintf(tw, "EXIT POINTS:\t%d\n", len(definition.ExitPoints))

	return nil
}

// checkAndStartDependencies verifies that all mission dependencies are installed and running.
// If --start-dependencies flag is set, it will automatically start any stopped dependencies.
// Otherwise, it will print a warning about stopped dependencies.
func checkAndStartDependencies(ctx context.Context, client *dclient.Client, workflowPath string, verbose bool) error {
	// Parse mission definition to extract dependencies
	def, err := mission.ParseDefinition(workflowPath)
	if err != nil {
		return fmt.Errorf("failed to parse mission definition: %w", err)
	}

	// Build dependency map from mission definition
	dependencies := make(map[string]string) // map[name]kind

	// Extract dependencies from mission nodes
	for _, node := range def.Nodes {
		switch node.Type {
		case mission.NodeTypeAgent:
			if node.AgentName != "" {
				dependencies[node.AgentName] = "agent"
			}
		case mission.NodeTypeTool:
			if node.ToolName != "" {
				dependencies[node.ToolName] = "tool"
			}
		case mission.NodeTypePlugin:
			if node.PluginName != "" {
				dependencies[node.PluginName] = "plugin"
			}
		}
	}

	// Extract explicit dependencies from mission definition
	if def.Dependencies != nil {
		for _, agent := range def.Dependencies.Agents {
			dependencies[agent] = "agent"
		}
		for _, tool := range def.Dependencies.Tools {
			dependencies[tool] = "tool"
		}
		for _, plugin := range def.Dependencies.Plugins {
			dependencies[plugin] = "plugin"
		}
	}

	// If no dependencies, nothing to check
	if len(dependencies) == 0 {
		if verbose {
			fmt.Println("No component dependencies to check")
		}
		return nil
	}

	// Query component status from daemon
	notInstalled := make([]string, 0)
	notRunning := make([]string, 0)

	// Check agents
	agents, err := client.ListAgents(ctx)
	if err != nil {
		return fmt.Errorf("failed to list agents: %w", err)
	}
	agentMap := make(map[string]dclient.AgentInfo)
	for _, agent := range agents {
		agentMap[agent.Name] = agent
	}

	// Check tools
	tools, err := client.ListTools(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tools: %w", err)
	}
	toolMap := make(map[string]dclient.ToolInfo)
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}

	// Check plugins
	plugins, err := client.ListPlugins(ctx)
	if err != nil {
		return fmt.Errorf("failed to list plugins: %w", err)
	}
	pluginMap := make(map[string]dclient.PluginInfo)
	for _, plugin := range plugins {
		pluginMap[plugin.Name] = plugin
	}

	// Verify each dependency
	for name, kind := range dependencies {
		switch kind {
		case "agent":
			if agent, exists := agentMap[name]; exists {
				if agent.Status != "running" {
					notRunning = append(notRunning, fmt.Sprintf("%s (agent)", name))
				}
			} else {
				notInstalled = append(notInstalled, fmt.Sprintf("%s (agent)", name))
			}
		case "tool":
			if tool, exists := toolMap[name]; exists {
				if tool.Status != "running" {
					notRunning = append(notRunning, fmt.Sprintf("%s (tool)", name))
				}
			} else {
				notInstalled = append(notInstalled, fmt.Sprintf("%s (tool)", name))
			}
		case "plugin":
			if plugin, exists := pluginMap[name]; exists {
				if plugin.Status != "running" {
					notRunning = append(notRunning, fmt.Sprintf("%s (plugin)", name))
				}
			} else {
				notInstalled = append(notInstalled, fmt.Sprintf("%s (plugin)", name))
			}
		}
	}

	// Report not installed components (fatal)
	if len(notInstalled) > 0 {
		fmt.Fprintf(os.Stderr, "Error: The following required components are not installed:\n")
		for _, comp := range notInstalled {
			fmt.Fprintf(os.Stderr, "  - %s\n", comp)
		}
		fmt.Fprintf(os.Stderr, "\nPlease install missing components before running the mission.\n")
		return fmt.Errorf("%d required component(s) not installed", len(notInstalled))
	}

	// Handle not running components
	if len(notRunning) > 0 {
		if missionStartDependencies {
			// Auto-start stopped dependencies
			fmt.Printf("Starting stopped dependencies:\n")
			for _, comp := range notRunning {
				// Extract name and kind
				parts := strings.Split(comp, " (")
				if len(parts) != 2 {
					continue
				}
				name := parts[0]
				kind := strings.TrimSuffix(parts[1], ")")

				fmt.Printf("  - %s: ", comp)

				var startErr error
				switch kind {
				case "agent":
					_, startErr = client.StartAgent(ctx, name)
				case "tool":
					_, startErr = client.StartTool(ctx, name)
				case "plugin":
					_, startErr = client.StartPlugin(ctx, name)
				}

				if startErr != nil {
					fmt.Printf("failed (%v)\n", startErr)
					return fmt.Errorf("failed to start %s: %w", comp, startErr)
				}
				fmt.Printf("started\n")
			}
			fmt.Println("All dependencies running. Executing mission...")
		} else {
			// Warn about stopped dependencies
			fmt.Fprintf(os.Stderr, "Warning: The following components are installed but not running:\n")
			for _, comp := range notRunning {
				fmt.Fprintf(os.Stderr, "  - %s\n", comp)
			}
			fmt.Fprintf(os.Stderr, "\nUse --start-dependencies to start them automatically, or run:\n")

			// Group by kind for cleaner instructions
			agentNames := make([]string, 0)
			toolNames := make([]string, 0)
			pluginNames := make([]string, 0)

			for _, comp := range notRunning {
				parts := strings.Split(comp, " (")
				if len(parts) != 2 {
					continue
				}
				name := parts[0]
				kind := strings.TrimSuffix(parts[1], ")")

				switch kind {
				case "agent":
					agentNames = append(agentNames, name)
				case "tool":
					toolNames = append(toolNames, name)
				case "plugin":
					pluginNames = append(pluginNames, name)
				}
			}

			for _, name := range agentNames {
				fmt.Fprintf(os.Stderr, "  gibson agent start %s\n", name)
			}
			for _, name := range toolNames {
				fmt.Fprintf(os.Stderr, "  gibson tool start %s\n", name)
			}
			for _, name := range pluginNames {
				fmt.Fprintf(os.Stderr, "  gibson plugin start %s\n", name)
			}
			fmt.Fprintf(os.Stderr, "\nProceeding with mission execution anyway...\n\n")
		}
	} else if verbose {
		fmt.Printf("All %d dependencies are running\n", len(dependencies))
	}

	return nil
}
