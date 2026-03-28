package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	"github.com/zero-day-ai/gibson/internal/checkpoint"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
)

// Checkpoint CLI command group for managing mission checkpoints
var checkpointCmd = &cobra.Command{
	Use:   "checkpoint",
	Short: "Manage mission checkpoints",
	Long: `Commands for listing, inspecting, restoring, and deleting checkpoints.

Checkpoints represent saved execution states that enable mission pause/resume,
recovery from failures, and thread branching for exploring alternative paths.`,
}

// List command: gibson checkpoint list [--mission-id ID] [--thread-id ID] [--limit N] [--json]
var checkpointListCmd = &cobra.Command{
	Use:   "list",
	Short: "List checkpoints for a mission or thread",
	Long: `List all checkpoints for a specific mission or thread.

Checkpoints are displayed in reverse chronological order (newest first).
Use --mission-id to filter by mission, or --thread-id for a specific thread.
Without filters, shows recent checkpoints across all missions.`,
	Example: `  # List checkpoints for a mission
  gibson checkpoint list --mission-id mission-20260107-153045-abc123

  # List checkpoints for a specific thread
  gibson checkpoint list --thread-id thread-xyz789

  # List with JSON output
  gibson checkpoint list --mission-id mission-123 --json

  # Limit results
  gibson checkpoint list --mission-id mission-123 --limit 10`,
	RunE: runCheckpointList,
}

// Inspect command: gibson checkpoint inspect <checkpoint-id> [--json]
var checkpointInspectCmd = &cobra.Command{
	Use:   "inspect <checkpoint-id>",
	Short: "Show detailed checkpoint information",
	Long: `Display detailed information about a specific checkpoint including:
  - Checkpoint metadata (ID, thread, created time)
  - Mission execution state (current node, pending nodes)
  - Node states and completion status
  - Memory sizes and data integrity
  - Findings discovered up to this point`,
	Example: `  # Inspect a checkpoint
  gibson checkpoint inspect chk-20260107-153100-def456

  # JSON output for scripting
  gibson checkpoint inspect chk-20260107-153100-def456 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runCheckpointInspect,
}

// Restore command: gibson checkpoint restore <checkpoint-id> [--mission-id ID] [--dry-run]
var checkpointRestoreCmd = &cobra.Command{
	Use:   "restore <checkpoint-id>",
	Short: "Restore a mission from a checkpoint",
	Long: `Restore mission execution from a saved checkpoint.

This creates a new mission run from the checkpoint state, allowing you to
resume execution from that point. The original mission and checkpoint are
preserved.

IMPORTANT: Restoration requires confirmation unless --force is used.`,
	Example: `  # Restore with confirmation
  gibson checkpoint restore chk-20260107-153100-def456

  # Force restore without confirmation
  gibson checkpoint restore chk-20260107-153100-def456 --force

  # Dry-run to preview without executing
  gibson checkpoint restore chk-20260107-153100-def456 --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: runCheckpointRestore,
}

// Delete command: gibson checkpoint delete <checkpoint-id> [--force] [--thread]
var checkpointDeleteCmd = &cobra.Command{
	Use:   "delete <checkpoint-id>",
	Short: "Delete a checkpoint or thread's checkpoints",
	Long: `Delete a specific checkpoint or all checkpoints for a thread.

DESTRUCTIVE OPERATION: Deleted checkpoints cannot be recovered.

Use --thread flag to delete all checkpoints for the thread instead of just one.
This is useful for cleaning up completed or abandoned execution branches.

IMPORTANT: Deletion requires confirmation unless --force is used.`,
	Example: `  # Delete a single checkpoint with confirmation
  gibson checkpoint delete chk-20260107-153100-def456

  # Force delete without confirmation
  gibson checkpoint delete chk-20260107-153100-def456 --force

  # Delete all checkpoints for a thread
  gibson checkpoint delete --thread thread-xyz789 --force`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCheckpointDelete,
}

// Threads subcommand: gibson checkpoint threads [--mission-id ID] [--json]
var checkpointThreadsCmd = &cobra.Command{
	Use:   "threads",
	Short: "List threads for a mission",
	Long: `Display all execution threads for a mission.

Threads represent branching execution paths from checkpoints. This is useful for:
  - Viewing parallel execution strategies
  - Comparing branch outcomes
  - Understanding execution history

The primary thread is marked with an indicator. Branch threads show their
parent thread and branch point.`,
	Example: `  # List threads for a mission
  gibson checkpoint threads --mission-id mission-20260107-153045-abc123

  # JSON output for scripting
  gibson checkpoint threads --mission-id mission-123 --json`,
	RunE: runCheckpointThreads,
}

// Flags
var (
	// List flags
	checkpointMissionID string
	checkpointThreadID  string
	checkpointLimit     int
	checkpointJSON      bool

	// Restore flags
	checkpointRestoreForce  bool
	checkpointRestoreDryRun bool

	// Delete flags
	checkpointDeleteForce  bool
	checkpointDeleteThread bool
)

func init() {
	// Register subcommands
	checkpointCmd.AddCommand(checkpointListCmd)
	checkpointCmd.AddCommand(checkpointInspectCmd)
	checkpointCmd.AddCommand(checkpointRestoreCmd)
	checkpointCmd.AddCommand(checkpointDeleteCmd)
	checkpointCmd.AddCommand(checkpointThreadsCmd)

	// List flags
	checkpointListCmd.Flags().StringVar(&checkpointMissionID, "mission-id", "", "Filter by mission ID")
	checkpointListCmd.Flags().StringVar(&checkpointThreadID, "thread-id", "", "Filter by thread ID")
	checkpointListCmd.Flags().IntVar(&checkpointLimit, "limit", 50, "Maximum number of checkpoints to show")
	checkpointListCmd.Flags().BoolVar(&checkpointJSON, "json", false, "Output in JSON format")

	// Inspect flags
	checkpointInspectCmd.Flags().BoolVar(&checkpointJSON, "json", false, "Output in JSON format")

	// Restore flags
	checkpointRestoreCmd.Flags().BoolVar(&checkpointRestoreForce, "force", false, "Skip confirmation prompt")
	checkpointRestoreCmd.Flags().BoolVar(&checkpointRestoreDryRun, "dry-run", false, "Preview without executing")

	// Delete flags
	checkpointDeleteCmd.Flags().BoolVar(&checkpointDeleteForce, "force", false, "Skip confirmation prompt")
	checkpointDeleteCmd.Flags().BoolVar(&checkpointDeleteThread, "thread", false, "Delete all checkpoints for a thread")

	// Threads flags
	checkpointThreadsCmd.Flags().StringVar(&checkpointMissionID, "mission-id", "", "Filter by mission ID (required)")
	checkpointThreadsCmd.Flags().BoolVar(&checkpointJSON, "json", false, "Output in JSON format")
	checkpointThreadsCmd.MarkFlagRequired("mission-id")
}

// runCheckpointList lists checkpoints for a mission or thread
func runCheckpointList(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Checkpoint listing requires daemon
	client, err := daemonclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "checkpoint listing requires daemon", err)
	}
	defer client.Close()

	// Validate flags
	if checkpointMissionID == "" && checkpointThreadID == "" {
		return internal.WrapError(internal.ExitConfigError, "must specify --mission-id or --thread-id", nil)
	}

	// Get checkpoints from daemon
	var checkpoints []CheckpointInfo
	if checkpointMissionID != "" {
		// Get all checkpoints for the mission
		missionCheckpoints, err := client.GetMissionCheckpoints(ctx, checkpointMissionID)
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to get mission checkpoints", err)
		}

		// Convert to CheckpointInfo
		for _, cp := range missionCheckpoints {
			checkpoints = append(checkpoints, CheckpointInfo{
				CheckpointID:   cp.CheckpointID,
				CreatedAt:      cp.CreatedAt,
				CompletedNodes: cp.CompletedNodes,
				TotalNodes:     cp.TotalNodes,
				FindingsCount:  cp.FindingsCount,
			})
		}

		// Apply thread filter if specified
		if checkpointThreadID != "" {
			// TODO: Filter by thread ID - requires daemon API enhancement
			// For now, show warning
			fmt.Fprintf(os.Stderr, "Warning: --thread-id filter not yet implemented\n")
		}
	}

	// Apply limit
	if len(checkpoints) > checkpointLimit {
		checkpoints = checkpoints[:checkpointLimit]
	}

	// Output results
	if checkpointJSON {
		return printCheckpointJSON(checkpoints)
	}
	return printCheckpointTable(checkpoints)
}

// runCheckpointInspect shows detailed checkpoint information
func runCheckpointInspect(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	checkpointID := args[0]

	// Checkpoint inspection requires daemon
	client, err := daemonclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "checkpoint inspection requires daemon", err)
	}
	defer client.Close()

	// TODO: Implement GetCheckpointDetails in daemon client
	// For now, show error message
	return internal.WrapError(internal.ExitError,
		fmt.Sprintf("checkpoint inspect not yet fully implemented (checkpoint: %s)", checkpointID),
		fmt.Errorf("daemon API enhancement required"))
}

// runCheckpointRestore restores a mission from a checkpoint
func runCheckpointRestore(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	checkpointID := args[0]

	// Dry-run mode
	if checkpointRestoreDryRun {
		fmt.Printf("DRY-RUN: Would restore from checkpoint %s\n", checkpointID)
		fmt.Println("Note: Actual restoration would:")
		fmt.Println("  1. Load checkpoint state from storage")
		fmt.Println("  2. Create new mission run with restored state")
		fmt.Println("  3. Resume execution from checkpoint node")
		return nil
	}

	// Confirmation prompt unless --force
	if !checkpointRestoreForce {
		fmt.Printf("This will restore mission execution from checkpoint %s.\n", checkpointID)
		fmt.Println("A new mission run will be created from this checkpoint state.")
		fmt.Print("\nType 'yes' to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return internal.WrapError(internal.ExitError, "failed to read confirmation", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" {
			fmt.Println("Restore cancelled")
			return nil
		}
	}

	// Checkpoint restoration requires daemon
	client, err := daemonclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "checkpoint restoration requires daemon", err)
	}
	defer client.Close()

	// TODO: Implement RestoreCheckpoint in daemon client
	// For now, show error message
	return internal.WrapError(internal.ExitError,
		fmt.Sprintf("checkpoint restore not yet fully implemented (checkpoint: %s)", checkpointID),
		fmt.Errorf("daemon API enhancement required"))
}

// runCheckpointDelete deletes a checkpoint or thread's checkpoints
func runCheckpointDelete(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Determine what to delete
	var target string
	var isThread bool

	if checkpointDeleteThread {
		if checkpointThreadID == "" {
			return internal.WrapError(internal.ExitConfigError, "--thread flag requires --thread-id", nil)
		}
		target = checkpointThreadID
		isThread = true
	} else {
		if len(args) == 0 {
			return internal.WrapError(internal.ExitConfigError, "checkpoint ID required", nil)
		}
		target = args[0]
		isThread = false
	}

	// Confirmation prompt unless --force
	if !checkpointDeleteForce {
		if isThread {
			fmt.Printf("This will delete ALL checkpoints for thread %s.\n", target)
		} else {
			fmt.Printf("This will delete checkpoint %s.\n", target)
		}
		fmt.Println("This action cannot be undone.")
		fmt.Print("\nType 'yes' to confirm: ")

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

	// Checkpoint deletion requires daemon
	client, err := daemonclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "checkpoint deletion requires daemon", err)
	}
	defer client.Close()

	// TODO: Implement DeleteCheckpoint in daemon client
	// For now, show error message
	if isThread {
		return internal.WrapError(internal.ExitError,
			fmt.Sprintf("thread checkpoint deletion not yet fully implemented (thread: %s)", target),
			fmt.Errorf("daemon API enhancement required"))
	}
	return internal.WrapError(internal.ExitError,
		fmt.Sprintf("checkpoint deletion not yet fully implemented (checkpoint: %s)", target),
		fmt.Errorf("daemon API enhancement required"))
}

// runCheckpointThreads lists threads for a mission
func runCheckpointThreads(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Thread listing requires daemon
	client, err := daemonclient.RequireDaemon(ctx)
	if err != nil {
		return internal.WrapError(internal.ExitError, "thread listing requires daemon", err)
	}
	defer client.Close()

	// TODO: Implement GetMissionThreads in daemon client
	// For now, show error message
	return internal.WrapError(internal.ExitError,
		fmt.Sprintf("thread listing not yet fully implemented (mission: %s)", checkpointMissionID),
		fmt.Errorf("daemon API enhancement required"))
}

// Output formatting functions

// CheckpointInfo is a simplified checkpoint representation for CLI display
type CheckpointInfo struct {
	CheckpointID   string
	ThreadID       string
	CreatedAt      time.Time
	MissionID      string
	CompletedNodes int
	TotalNodes     int
	FindingsCount  int
	SizeBytes      int64
	Label          string
}

// printCheckpointTable prints checkpoints in human-readable table format
func printCheckpointTable(checkpoints []CheckpointInfo) error {
	if len(checkpoints) == 0 {
		fmt.Println("No checkpoints found")
		return nil
	}

	fmt.Printf("Found %d checkpoint(s)\n\n", len(checkpoints))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHECKPOINT ID\tCREATED\tNODES\tFINDINGS\tSIZE\tLABEL")

	for _, cp := range checkpoints {
		createdStr := cp.CreatedAt.Format("2006-01-02 15:04:05")
		nodesStr := fmt.Sprintf("%d/%d", cp.CompletedNodes, cp.TotalNodes)
		sizeStr := formatBytes(cp.SizeBytes)
		labelStr := cp.Label
		if labelStr == "" {
			labelStr = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			cp.CheckpointID, createdStr, nodesStr, cp.FindingsCount, sizeStr, labelStr)
	}

	w.Flush()
	return nil
}

// printCheckpointJSON prints checkpoints in JSON format for scripting
func printCheckpointJSON(checkpoints []CheckpointInfo) error {
	data, err := json.MarshalIndent(checkpoints, "", "  ")
	if err != nil {
		return internal.WrapError(internal.ExitError, "failed to marshal JSON", err)
	}
	fmt.Println(string(data))
	return nil
}

// printCheckpointDetails prints detailed information about a single checkpoint
func printCheckpointDetails(cp *checkpoint.Checkpoint) error {
	if cp == nil {
		return fmt.Errorf("checkpoint is nil")
	}

	fmt.Printf("\nCheckpoint Details\n")
	fmt.Printf("==================\n\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ID:\t%s\n", cp.ID)
	fmt.Fprintf(w, "Thread ID:\t%s\n", cp.ThreadID)
	fmt.Fprintf(w, "Mission ID:\t%s\n", cp.MissionID)
	fmt.Fprintf(w, "Created:\t%s\n", cp.CreatedAt.Format("2006-01-02 15:04:05"))

	if cp.ParentID != "" {
		fmt.Fprintf(w, "Parent:\t%s\n", cp.ParentID)
	}

	if cp.Label != "" {
		fmt.Fprintf(w, "Label:\t%s\n", cp.Label)
	}

	fmt.Fprintf(w, "\nExecution State:\n")
	fmt.Fprintf(w, "Current Node:\t%s\n", cp.CurrentNodeID)
	fmt.Fprintf(w, "Completed Nodes:\t%d\n", len(cp.CompletedNodes))
	fmt.Fprintf(w, "Pending Nodes:\t%d\n", len(cp.PendingNodes))

	if len(cp.Findings) > 0 {
		fmt.Fprintf(w, "Findings:\t%d\n", len(cp.Findings))
	}

	fmt.Fprintf(w, "\nStorage:\n")
	fmt.Fprintf(w, "Size:\t%s\n", formatBytes(cp.SizeBytes))
	fmt.Fprintf(w, "Compressed:\t%v\n", cp.Compressed)
	fmt.Fprintf(w, "Encrypted:\t%v\n", cp.Encrypted)
	if cp.Encrypted && cp.KeyID != "" {
		fmt.Fprintf(w, "Key ID:\t%s\n", cp.KeyID)
	}

	fmt.Fprintf(w, "\nIntegrity:\n")
	fmt.Fprintf(w, "Checksum:\t%s\n", cp.Checksum)
	fmt.Fprintf(w, "Version:\t%d\n", cp.Version)

	// Show in-progress node if present
	if cp.InProgressNode != nil {
		fmt.Fprintf(w, "\nIn-Progress Node:\n")
		fmt.Fprintf(w, "Node ID:\t%s\n", cp.InProgressNode.NodeID)
		fmt.Fprintf(w, "Started:\t%s\n", cp.InProgressNode.StartedAt.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(w, "Elapsed:\t%s\n", cp.InProgressNode.Elapsed)
		fmt.Fprintf(w, "Retry Count:\t%d\n", cp.InProgressNode.RetryCount)
	}

	// Show approval state if present
	if cp.ApprovalState != nil {
		fmt.Fprintf(w, "\nApproval State:\n")
		fmt.Fprintf(w, "Status:\t%s\n", cp.ApprovalState.Status)
		fmt.Fprintf(w, "Requested:\t%s\n", cp.ApprovalState.RequestedAt.Format("2006-01-02 15:04:05"))
		if cp.ApprovalState.Decision != nil && cp.ApprovalState.Decision.ApprovedBy != "" {
			fmt.Fprintf(w, "Approved By:\t%s\n", cp.ApprovalState.Decision.ApprovedBy)
		}
	}

	// Show metadata if present
	if len(cp.Metadata) > 0 {
		fmt.Fprintf(w, "\nMetadata:\n")
		for k, v := range cp.Metadata {
			fmt.Fprintf(w, "%s:\t%s\n", k, v)
		}
	}

	w.Flush()
	fmt.Println()
	return nil
}

// formatBytes formats byte sizes in human-readable format
func formatBytes(bytes int64) string {
	if bytes == 0 {
		return "0 B"
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"B", "KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp+1])
}
