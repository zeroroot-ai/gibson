package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zero-day-ai/gibson/cmd/gibson/component"
	"github.com/zero-day-ai/gibson/cmd/gibson/internal"
	internalcomponent "github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon"
	daemonclient "github.com/zero-day-ai/gibson/internal/daemon/client"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display system health and status",
	Long: `Display overall system status including:
  - Running agents and plugins with port/PID information
  - Database connectivity status
  - Configured LLM providers with health status
  - Overall system health assessment`,
	RunE: runStatus,
}

// SystemStatus represents the complete system status
type SystemStatus struct {
	OverallHealth types.HealthStatus  `json:"overall_health"`
	Registry      RegistryStatus      `json:"registry"`
	Components    ComponentsStatus    `json:"components"`
	Database      DatabaseStatus      `json:"database"`
	LLMProviders  []LLMProviderStatus `json:"llm_providers"`
	CheckedAt     time.Time           `json:"checked_at"`
}

// ComponentsStatus represents the status of all components
type ComponentsStatus struct {
	Agents  []ComponentInfo `json:"agents"`
	Tools   []ComponentInfo `json:"tools"`
	Plugins []ComponentInfo `json:"plugins"`
}

// ComponentInfo represents information about a single component
type ComponentInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Port   int    `json:"port,omitempty"`
	PID    int    `json:"pid,omitempty"`
}

// DatabaseStatus represents database health information
type DatabaseStatus struct {
	Connected bool   `json:"connected"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Error     string `json:"error,omitempty"`
}

// LLMProviderStatus represents LLM provider health information
type LLMProviderStatus struct {
	Name         string             `json:"name"`
	Configured   bool               `json:"configured"`
	HealthStatus types.HealthStatus `json:"health_status"`
}

// RegistryStatus represents registry health information
type RegistryStatus struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	Healthy  bool   `json:"healthy"`
	Uptime   string `json:"uptime"`
	Services int    `json:"services"`
	Error    string `json:"error,omitempty"`
}

func init() {
	// Add --json flag for structured output
	statusCmd.Flags().Bool("json", false, "Output status in JSON format")
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Parse global flags
	flags, err := ParseGlobalFlags(cmd)
	if err != nil {
		return err
	}

	// Determine home directory
	homeDir := flags.HomeDir
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Check if JSON output is requested
	jsonOutput, _ := cmd.Flags().GetBool("json")
	format := internal.FormatText
	if jsonOutput {
		format = internal.FormatJSON
	}

	// Create formatter
	formatter := internal.NewFormatter(format, cmd.OutOrStdout())

	// Check for daemon client in context - use daemon status if available
	if client := component.GetDaemonClient(ctx); client != nil {
		if dc, ok := client.(*daemonclient.Client); ok {
			return showDaemonStatus(cmd, dc, formatter, format, homeDir)
		}
	}

	// No daemon client - collect local system status
	status := collectSystemStatus(ctx, homeDir)

	// Output status
	if format == internal.FormatJSON {
		return formatter.PrintJSON(status)
	}

	// Text output
	return printTextStatus(formatter, status)
}

// showDaemonStatus queries the daemon for status and displays it
func showDaemonStatus(cmd *cobra.Command, client *daemonclient.Client, formatter internal.Formatter, format internal.OutputFormat, homeDir string) error {
	ctx := cmd.Context()

	// Query daemon for status via gRPC
	daemonStatus, err := client.Status(ctx)
	if err != nil {
		// If we can't reach the daemon, fall back to file-based status
		if strings.Contains(err.Error(), "daemon not responding") {
			return showDaemonFileStatus(cmd, formatter, format, homeDir)
		}
		return fmt.Errorf("failed to get daemon status: %w", err)
	}

	// Build system status from daemon response
	status := SystemStatus{
		CheckedAt:     time.Now(),
		OverallHealth: types.Healthy("daemon running"),
		Registry: RegistryStatus{
			Type:     daemonStatus.RegistryType,
			Endpoint: daemonStatus.RegistryAddr,
			Healthy:  true,
			Uptime:   daemonStatus.Uptime,
			Services: int(daemonStatus.AgentCount), // Total components registered
		},
		Database:     checkDatabaseStatus(ctx, homeDir),
		LLMProviders: checkLLMProviders(ctx, homeDir),
	}

	// Output based on format
	if format == internal.FormatJSON {
		return formatter.PrintJSON(status)
	}

	// Print daemon-specific info at the top
	fmt.Println()
	fmt.Println("Daemon:")
	fmt.Printf("  ✓ Running:      yes\n")
	fmt.Printf("    PID:          %d\n", daemonStatus.PID)
	fmt.Printf("    gRPC Address: %s\n", daemonStatus.GRPCAddress)
	fmt.Printf("    Uptime:       %s\n", daemonStatus.Uptime)
	fmt.Println()

	// Print the rest of the status
	return printTextStatus(formatter, status)
}

// showDaemonFileStatus shows status from daemon files when RPC not available
func showDaemonFileStatus(cmd *cobra.Command, formatter internal.Formatter, format internal.OutputFormat, homeDir string) error {
	ctx := cmd.Context()

	// Check if we're in remote daemon mode
	if remoteAddr := os.Getenv(daemonclient.EnvDaemonAddress); remoteAddr != "" {
		// In remote mode, we shouldn't be checking local files
		status := SystemStatus{
			CheckedAt:     time.Now(),
			OverallHealth: types.Degraded("remote daemon mode - local status unavailable"),
			Registry: RegistryStatus{
				Healthy: false,
				Error:   fmt.Sprintf("using remote daemon at %s", remoteAddr),
			},
			Database:     DatabaseStatus{Connected: false, Error: "remote daemon mode"},
			LLMProviders: []LLMProviderStatus{},
		}

		if format == internal.FormatJSON {
			return formatter.PrintJSON(status)
		}
		return printTextStatus(formatter, status)
	}

	// Read daemon info from file
	infoPath := filepath.Join(homeDir, "daemon.json")
	info, err := daemon.ReadDaemonInfo(infoPath)
	if err != nil {
		// No daemon info - show not running
		status := SystemStatus{
			CheckedAt:     time.Now(),
			OverallHealth: types.Degraded("daemon not running"),
			Registry: RegistryStatus{
				Healthy: false,
				Error:   "daemon not running",
			},
			Database:     checkDatabaseStatus(ctx, homeDir),
			LLMProviders: checkLLMProviders(ctx, homeDir),
		}

		if format == internal.FormatJSON {
			return formatter.PrintJSON(status)
		}
		return printTextStatus(formatter, status)
	}

	// Calculate uptime
	uptime := time.Since(info.StartTime)

	status := SystemStatus{
		CheckedAt:     time.Now(),
		OverallHealth: types.Healthy("daemon running"),
		Registry: RegistryStatus{
			Type:    "daemon",
			Healthy: true,
			Uptime:  formatDuration(uptime),
		},
		Database:     checkDatabaseStatus(ctx, homeDir),
		LLMProviders: checkLLMProviders(ctx, homeDir),
	}

	// Add daemon-specific info
	fmt.Println()
	fmt.Println("Daemon:")
	fmt.Printf("  ✓ Running:      yes\n")
	fmt.Printf("    PID:          %d\n", info.PID)
	fmt.Printf("    gRPC Address: %s\n", info.GRPCAddress)
	fmt.Printf("    Uptime:       %s\n", formatDuration(uptime))
	fmt.Printf("    Version:      %s\n", info.Version)
	fmt.Println()

	if format == internal.FormatJSON {
		return formatter.PrintJSON(status)
	}
	return printTextStatus(formatter, status)
}

// collectSystemStatus collects status from all subsystems
func collectSystemStatus(ctx context.Context, homeDir string) SystemStatus {
	status := SystemStatus{
		CheckedAt: time.Now(),
	}

	// Check registry
	status.Registry = checkRegistryStatus(ctx, homeDir)

	// Check components
	status.Components = checkComponentsStatus(homeDir)

	// Check database
	status.Database = checkDatabaseStatus(ctx, homeDir)

	// Check LLM providers
	status.LLMProviders = checkLLMProviders(ctx, homeDir)

	// Determine overall health
	status.OverallHealth = determineOverallHealth(status)

	return status
}

// checkRegistryStatus checks the registry status
func checkRegistryStatus(ctx context.Context, homeDir string) RegistryStatus {
	regStatus := RegistryStatus{
		Healthy: false,
	}

	// Check if we're in remote daemon mode
	if remoteAddr := os.Getenv(daemonclient.EnvDaemonAddress); remoteAddr != "" {
		regStatus.Type = "remote-daemon"
		regStatus.Endpoint = remoteAddr
		regStatus.Error = "remote daemon - status not available locally"
		return regStatus
	}

	// In daemon mode, registry is managed by daemon
	// Check daemon.json for info
	infoPath := filepath.Join(homeDir, "daemon.json")
	info, err := daemon.ReadDaemonInfo(infoPath)
	if err != nil {
		regStatus.Error = "daemon not running (no registry available)"
		return regStatus
	}

	// Daemon is running - registry should be available
	regStatus.Type = "daemon-managed"
	regStatus.Endpoint = info.GRPCAddress
	regStatus.Healthy = true
	regStatus.Uptime = formatDuration(time.Since(info.StartTime))

	return regStatus
}

// formatDuration formats a duration in a human-readable format (e.g., "2h 15m")
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if minutes == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

// checkComponentsStatus checks the status of all components
// NOTE: Component data is now stored in etcd, not SQLite.
// This function returns empty status for backwards compatibility.
func checkComponentsStatus(homeDir string) ComponentsStatus {
	componentStatus := ComponentsStatus{
		Agents:  []ComponentInfo{},
		Tools:   []ComponentInfo{},
		Plugins: []ComponentInfo{},
	}

	// Component data is now stored in etcd, not SQLite
	// Return empty status for backwards compatibility
	return componentStatus
}

// checkDatabaseStatus checks Redis connectivity and status
func checkDatabaseStatus(ctx context.Context, homeDir string) DatabaseStatus {
	dbStatus := DatabaseStatus{
		Connected: false,
		Path:      "Redis (state backend)",
	}

	// Load configuration to get Redis settings
	cfg, err := loadGlobalConfig()
	if err != nil {
		dbStatus.Error = fmt.Sprintf("failed to load config: %v", err)
		return dbStatus
	}

	// Create StateClient for Redis health check
	stateCfg := &state.Config{
		URL:         cfg.Redis.URL,
		Database:    cfg.Redis.Database,
		Password:    cfg.Redis.Password,
		PoolSize:    cfg.Redis.PoolSize,
		DialTimeout: cfg.Redis.ConnectTimeout,
		ReadTimeout: cfg.Redis.ReadTimeout,
	}
	stateCfg.ApplyDefaults()

	stateClient, err := state.NewStateClient(stateCfg)
	if err != nil {
		dbStatus.Error = fmt.Sprintf("failed to connect to Redis: %v", err)
		return dbStatus
	}
	defer stateClient.Close()

	// Test connection with health check
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := stateClient.Health(healthCtx); err != nil {
		dbStatus.Error = fmt.Sprintf("Redis health check failed: %v", err)
		return dbStatus
	}

	dbStatus.Connected = true
	dbStatus.Size = 0 // Redis doesn't expose size through state client
	return dbStatus
}

// checkLLMProviders checks configured LLM providers and their health
func checkLLMProviders(ctx context.Context, homeDir string) []LLMProviderStatus {
	providers := []LLMProviderStatus{}

	// Determine config file path
	configFile := config.DefaultConfigPath(homeDir)

	// Load configuration
	loader := config.NewConfigLoader(config.NewValidator())
	cfg, err := loader.LoadWithDefaults(configFile)
	if err != nil {
		// Config may not exist yet
		return providers
	}

	// Create LLM registry (in real implementation, this would be injected)
	registry := llm.NewLLMRegistry()

	// Check if default provider is configured
	if cfg.LLM.DefaultProvider != "" {
		// Try to get provider from registry
		provider, err := registry.GetProvider(cfg.LLM.DefaultProvider)
		if err != nil {
			// Provider not registered, add as unconfigured
			providers = append(providers, LLMProviderStatus{
				Name:         cfg.LLM.DefaultProvider,
				Configured:   false,
				HealthStatus: types.Unhealthy("provider not registered"),
			})
		} else {
			// Check provider health
			health := provider.Health(ctx)
			providers = append(providers, LLMProviderStatus{
				Name:         cfg.LLM.DefaultProvider,
				Configured:   true,
				HealthStatus: health,
			})
		}
	}

	// If no providers configured, note that
	if len(providers) == 0 {
		providers = append(providers, LLMProviderStatus{
			Name:         "none",
			Configured:   false,
			HealthStatus: types.Unhealthy("no LLM providers configured"),
		})
	}

	return providers
}

// determineOverallHealth determines overall system health based on subsystems
func determineOverallHealth(status SystemStatus) types.HealthStatus {
	// Count health states
	healthyCount := 0
	unhealthyCount := 0
	issues := []string{}

	// Check database
	if !status.Database.Connected {
		unhealthyCount++
		issues = append(issues, "database unavailable")
	} else {
		healthyCount++
	}

	// Check LLM providers
	hasHealthyProvider := false
	for _, provider := range status.LLMProviders {
		if provider.Configured && provider.HealthStatus.IsHealthy() {
			hasHealthyProvider = true
			break
		}
	}
	if !hasHealthyProvider {
		unhealthyCount++
		issues = append(issues, "no healthy LLM providers")
	} else {
		healthyCount++
	}

	// Check for running components
	totalComponents := len(status.Components.Agents) +
		len(status.Components.Tools) +
		len(status.Components.Plugins)

	runningComponents := 0
	for _, agent := range status.Components.Agents {
		if agent.Status == internalcomponent.ComponentStatusRunning.String() {
			runningComponents++
		}
	}
	for _, tool := range status.Components.Tools {
		if tool.Status == internalcomponent.ComponentStatusRunning.String() {
			runningComponents++
		}
	}
	for _, plugin := range status.Components.Plugins {
		if plugin.Status == internalcomponent.ComponentStatusRunning.String() {
			runningComponents++
		}
	}

	// Determine overall status
	if unhealthyCount == 0 {
		if totalComponents == 0 {
			return types.Healthy("system initialized, no components installed")
		}
		if runningComponents == 0 {
			return types.Degraded("system healthy, no components running")
		}
		return types.Healthy(fmt.Sprintf("all systems operational (%d/%d components running)",
			runningComponents, totalComponents))
	} else if healthyCount > 0 {
		return types.Degraded(fmt.Sprintf("system degraded: %v", issues))
	} else {
		return types.Unhealthy(fmt.Sprintf("system unhealthy: %v", issues))
	}
}

// printTextStatus prints status in human-readable text format
func printTextStatus(formatter internal.Formatter, status SystemStatus) error {
	// Print overall health
	healthSymbol := "✓"
	if status.OverallHealth.IsDegraded() {
		healthSymbol = "⚠"
	} else if status.OverallHealth.IsUnhealthy() {
		healthSymbol = "✗"
	}

	fmt.Printf("\n%s Overall Status: %s\n", healthSymbol, status.OverallHealth.State)
	if status.OverallHealth.Message != "" {
		fmt.Printf("  %s\n", status.OverallHealth.Message)
	}
	fmt.Println()

	// Print registry status
	fmt.Println("Registry:")
	if status.Registry.Healthy {
		fmt.Printf("  ✓ Type:     %s\n", status.Registry.Type)
		fmt.Printf("    Endpoint: %s\n", status.Registry.Endpoint)
		fmt.Printf("    Healthy:  yes\n")
		fmt.Printf("    Uptime:   %s\n", status.Registry.Uptime)
		fmt.Printf("    Services: %d\n", status.Registry.Services)
	} else {
		fmt.Printf("  ✗ Type:     %s\n", status.Registry.Type)
		if status.Registry.Endpoint != "" {
			fmt.Printf("    Endpoint: %s\n", status.Registry.Endpoint)
		}
		fmt.Printf("    Healthy:  no\n")
		if status.Registry.Error != "" {
			fmt.Printf("    Error:    %s\n", status.Registry.Error)
		}
	}
	fmt.Println()

	// Print database status
	fmt.Println("Database:")
	if status.Database.Connected {
		fmt.Printf("  ✓ Connected: %s\n", status.Database.Path)
		fmt.Printf("    Size: %d bytes\n", status.Database.Size)
	} else {
		fmt.Printf("  ✗ Not connected\n")
		if status.Database.Error != "" {
			fmt.Printf("    Error: %s\n", status.Database.Error)
		}
	}
	fmt.Println()

	// Print LLM providers
	fmt.Println("LLM Providers:")
	if len(status.LLMProviders) == 0 {
		fmt.Println("  No providers configured")
	} else {
		for _, provider := range status.LLMProviders {
			symbol := "✓"
			if !provider.Configured {
				symbol = "✗"
			} else if provider.HealthStatus.IsUnhealthy() {
				symbol = "✗"
			} else if provider.HealthStatus.IsDegraded() {
				symbol = "⚠"
			}

			fmt.Printf("  %s %s: %s\n", symbol, provider.Name, provider.HealthStatus.State)
			if provider.HealthStatus.Message != "" {
				fmt.Printf("    %s\n", provider.HealthStatus.Message)
			}
		}
	}
	fmt.Println()

	// Print components
	if len(status.Components.Agents) > 0 {
		fmt.Println("Agents:")
		headers := []string{"Name", "Status", "Port", "PID"}
		rows := [][]string{}
		for _, agent := range status.Components.Agents {
			port := "-"
			pid := "-"
			if agent.Port > 0 {
				port = fmt.Sprintf("%d", agent.Port)
			}
			if agent.PID > 0 {
				pid = fmt.Sprintf("%d", agent.PID)
			}
			rows = append(rows, []string{agent.Name, agent.Status, port, pid})
		}
		formatter.PrintTable(headers, rows)
		fmt.Println()
	}

	if len(status.Components.Tools) > 0 {
		fmt.Println("Tools:")
		headers := []string{"Name", "Status", "Port", "PID"}
		rows := [][]string{}
		for _, tool := range status.Components.Tools {
			port := "-"
			pid := "-"
			if tool.Port > 0 {
				port = fmt.Sprintf("%d", tool.Port)
			}
			if tool.PID > 0 {
				pid = fmt.Sprintf("%d", tool.PID)
			}
			rows = append(rows, []string{tool.Name, tool.Status, port, pid})
		}
		formatter.PrintTable(headers, rows)
		fmt.Println()
	}

	if len(status.Components.Plugins) > 0 {
		fmt.Println("Plugins:")
		headers := []string{"Name", "Status", "Port", "PID"}
		rows := [][]string{}
		for _, plugin := range status.Components.Plugins {
			port := "-"
			pid := "-"
			if plugin.Port > 0 {
				port = fmt.Sprintf("%d", plugin.Port)
			}
			if plugin.PID > 0 {
				pid = fmt.Sprintf("%d", plugin.PID)
			}
			rows = append(rows, []string{plugin.Name, plugin.Status, port, pid})
		}
		formatter.PrintTable(headers, rows)
		fmt.Println()
	}

	return nil
}
