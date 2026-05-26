package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zeroroot-ai/gibson/internal/component"
)

const (
	// registryPollInterval is how often to check registry for component registration
	registryPollInterval = 500 * time.Millisecond

	// registryStartTimeout is how long to wait for component to register
	registryStartTimeout = 30 * time.Second

	// registryStopTimeout is how long to wait for graceful shutdown
	registryStopTimeout = 10 * time.Second
)

// startComponentProcess starts a component process and waits for it to register.
//
// This is the core lifecycle function that:
//  1. Finds an available port
//  2. Launches the component binary with appropriate args and environment
//  3. Polls the registry until the component registers
//  4. Returns the PID, port, and log path
//
// If the component fails to register within the timeout, the process is killed.
// The pluginConfig parameter allows passing plugin-specific configuration as environment variables.
func startComponentProcess(
	ctx context.Context,
	comp *component.Component,
	reg component.ComponentRegistry,
	tenant string,
	registryEndpoint string,
	homeDir string,
	pluginConfig map[string]string,
) (port int, pid int, logPath string, error error) {
	// Validate component has required fields
	if comp.Manifest == nil {
		return 0, 0, "", fmt.Errorf("component manifest is required")
	}
	if comp.BinPath == "" {
		return 0, 0, "", fmt.Errorf("component binary path is required")
	}

	// Find available port
	port, err := findAvailablePort()
	if err != nil {
		return 0, 0, "", fmt.Errorf("failed to find available port: %w", err)
	}

	// Prepare command arguments - start with runtime args if specified
	var args []string
	if comp.Manifest.Runtime != nil {
		args = append(args, comp.Manifest.Runtime.GetArgs()...)
	}
	args = append(args, "--port", strconv.Itoa(port))

	// Add health endpoint flag if specified in runtime config
	if comp.Manifest.Runtime != nil && comp.Manifest.Runtime.HealthURL != "" {
		args = append(args, "--health-endpoint", comp.Manifest.Runtime.HealthURL)
	}

	// Create command
	cmd := exec.Command(comp.BinPath, args...)

	// Set environment variables
	env := os.Environ()
	if comp.Manifest.Runtime != nil {
		for k, v := range comp.Manifest.Runtime.GetEnv() {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Add plugin-specific config as environment variables
	// Convert config keys to uppercase with GIBSON_PLUGIN_ prefix
	// e.g., "hackerone_api_key" -> "GIBSON_PLUGIN_HACKERONE_API_KEY"
	for k, v := range pluginConfig {
		envKey := "GIBSON_PLUGIN_" + strings.ToUpper(k)
		env = append(env, fmt.Sprintf("%s=%s", envKey, v))
	}

	// Add registry endpoints to environment
	env = append(env, fmt.Sprintf("GIBSON_REGISTRY_ENDPOINTS=%s", registryEndpoint))

	cmd.Env = env

	// Create log directory and file for component output
	logDir := filepath.Join(homeDir, "logs", string(comp.Kind))
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return 0, 0, "", fmt.Errorf("failed to create log directory: %w", err)
	}

	logPath = filepath.Join(logDir, fmt.Sprintf("%s.log", comp.Name))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, 0, "", fmt.Errorf("failed to create log file: %w", err)
	}

	// Write startup header to log
	fmt.Fprintf(logFile, "\n=== %s started at %s ===\n", comp.Name, time.Now().Format(time.RFC3339))
	fmt.Fprintf(logFile, "Port: %d\n", port)
	fmt.Fprintf(logFile, "Binary: %s\n", comp.BinPath)
	fmt.Fprintf(logFile, "Args: %v\n\n", args)

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Detach the child process from the parent's process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, 0, "", fmt.Errorf("failed to start process: %w", err)
	}

	// Don't close the log file - the child process owns it now

	pid = cmd.Process.Pid

	// Wait for component to register in registry
	if err := waitForRegistration(ctx, reg, tenant, string(comp.Kind), comp.Name, registryStartTimeout); err != nil {
		// Registration failed, kill the process
		_ = cmd.Process.Kill()
		return 0, 0, "", fmt.Errorf("component failed to register: %w", err)
	}

	return port, pid, logPath, nil
}

// stopComponentProcess stops a single component instance.
//
// This function:
//  1. Extracts the port from the registry endpoint
//  2. Finds the process ID using the port
//  3. Sends SIGTERM for graceful shutdown
//  4. Polls the registry for deregistration
//  5. Sends SIGKILL if graceful shutdown times out
func stopComponentProcess(
	ctx context.Context,
	instance component.ComponentInfo,
	reg component.ComponentRegistry,
	tenant string,
	force bool,
) error {
	// Extract port from endpoint (format: "host:port")
	endpoint := instance.Metadata["grpc_endpoint"]
	port, err := parsePortFromEndpoint(endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}

	// Find process by port
	pid, err := findProcessByPort(port)
	if err != nil {
		return fmt.Errorf("failed to find process for port %d: %w", port, err)
	}

	// Find the process
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// If force is true, send SIGKILL immediately
	if force {
		if err := process.Kill(); err != nil {
			if !strings.Contains(err.Error(), "process already finished") {
				return fmt.Errorf("failed to kill process: %w", err)
			}
		}
		// Wait a bit for kill to complete
		time.Sleep(time.Second)
		return nil
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// Process may already be dead
		if strings.Contains(err.Error(), "process already finished") {
			// Already finished, consider it success
			return nil
		}
		return fmt.Errorf("failed to send SIGTERM: %w", err)
	}

	// Wait for deregistration from registry with timeout
	stopCtx, cancel := context.WithTimeout(ctx, registryStopTimeout)
	defer cancel()

	if err := waitForDeregistration(stopCtx, reg, tenant, instance.Kind, instance.Name, instance.InstanceID); err != nil {
		// Timeout reached, send SIGKILL
		if err := process.Kill(); err != nil {
			if !strings.Contains(err.Error(), "process already finished") {
				return fmt.Errorf("failed to kill process: %w", err)
			}
		}
		// Wait a bit for kill to complete
		time.Sleep(time.Second)
	}

	return nil
}

// waitForRegistration polls the registry until the component appears.
func waitForRegistration(
	ctx context.Context,
	reg component.ComponentRegistry,
	tenant, kind, name string,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(registryPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for component to register")
		case <-ticker.C:
			instances, err := reg.Discover(ctx, tenant, kind, name)
			if err != nil {
				// Continue polling on transient errors
				continue
			}
			if len(instances) > 0 {
				// Component registered successfully
				return nil
			}
		}
	}
}

// waitForDeregistration polls the registry until a specific instance disappears.
func waitForDeregistration(
	ctx context.Context,
	reg component.ComponentRegistry,
	tenant, kind, name, instanceID string,
) error {
	ticker := time.NewTicker(registryPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for deregistration")
		case <-ticker.C:
			instances, err := reg.Discover(ctx, tenant, kind, name)
			if err != nil {
				// Continue polling on transient errors
				continue
			}

			// Check if our instance is still present
			found := false
			for _, instance := range instances {
				if instance.InstanceID == instanceID {
					found = true
					break
				}
			}

			if !found {
				// Instance deregistered successfully
				return nil
			}
		}
	}
}

// parsePortFromEndpoint extracts the port number from an endpoint string.
func parsePortFromEndpoint(endpoint string) (int, error) {
	// Handle unix sockets (not supported for port extraction)
	if strings.HasPrefix(endpoint, "unix://") {
		return 0, fmt.Errorf("unix sockets not supported for port-based process lookup")
	}

	// Extract port from "host:port" format
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid endpoint format: %s", endpoint)
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("invalid port number: %s", parts[1])
	}

	return port, nil
}

// findProcessByPort finds the PID of the process LISTENING on the specified port.
// IMPORTANT: Uses -sTCP:LISTEN to only match listening processes, not connected clients.
// Without this filter, lsof returns ALL processes associated with the port (listeners
// AND clients), and we could accidentally kill the wrong process (e.g., the daemon
// which has a gRPC client connection to an agent).
func findProcessByPort(port int) (int, error) {
	// Use lsof to find the process LISTENING on the port
	// -sTCP:LISTEN ensures we only get the listening process, not clients
	// -t returns just the PID
	cmd := exec.Command("lsof", "-t", "-sTCP:LISTEN", fmt.Sprintf("-i:%d", port))
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("lsof failed: %w", err)
	}

	// Parse PID from output
	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		return 0, fmt.Errorf("no process found listening on port %d", port)
	}

	// There should only be one listening process per port, but parse safely
	lines := strings.Split(pidStr, "\n")
	pid, err := strconv.Atoi(lines[0])
	if err != nil {
		return 0, fmt.Errorf("invalid PID: %s", lines[0])
	}

	return pid, nil
}

// findAvailablePort scans for an available port in the default range.
func findAvailablePort() (int, error) {
	// Use the same port range as the component lifecycle manager
	const portRangeStart = 50000
	const portRangeEnd = 60000

	for port := portRangeStart; port <= portRangeEnd; port++ {
		if isPortAvailable(port) {
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports in range %d-%d", portRangeStart, portRangeEnd)
}

// isPortAvailable checks if a port is available for use.
func isPortAvailable(port int) bool {
	conn, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(conn)

	var sockaddr syscall.SockaddrInet4
	sockaddr.Port = port
	copy(sockaddr.Addr[:], []byte{127, 0, 0, 1})

	err = syscall.Bind(conn, &sockaddr)
	if err != nil {
		return false
	}
	return true
}
