//go:build e2e
// +build e2e

// Package helpers — shape_validator.go implements JSON shape validation via a
// long-running Node.js subprocess that runs the dashboard's Zod schemas.
//
// Go cannot run Zod natively, so a single Node.js process (validate-schema.mjs)
// is kept alive for the lifetime of the test run. All schema validation calls
// are routed through newline-delimited JSON on stdin/stdout — no exec-per-call
// overhead.
//
// The Node.js script path is resolved relative to DASHBOARD_ROOT env var (if
// set) or derived from the REPO_ROOT env var.
//
// Requirements: R1.3, NFR Modularity (no third validation library).
// Design: Component 4.
package helpers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// ShapeValidator — manages the long-running Node.js subprocess
// ---------------------------------------------------------------------------

// ShapeValidator is a long-running Node.js subprocess that validates JSON
// payloads against Zod schemas. Call NewShapeValidator once per test suite
// and Close when done.
type ShapeValidator struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner

	mu      sync.Mutex       // serializes stdin writes and stdout reads
	seq     atomic.Int64     // monotonic request ID generator
	pending map[string]chan validateResponse
	closed  bool
}

// validateRequest is the JSON sent to the Node.js process on stdin.
type validateRequest struct {
	ID        string `json:"id"`
	SchemaRef string `json:"schemaRef"`
	Body      string `json:"body"`
}

// validateResponse is the JSON received from the Node.js process on stdout.
type validateResponse struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// nodeScriptPath returns the absolute path to validate-schema.mjs.
// Resolved in order: DASHBOARD_ROOT env var → REPO_ROOT env var → heuristic.
func nodeScriptPath() (string, error) {
	// DASHBOARD_ROOT: explicit override.
	if root := os.Getenv("DASHBOARD_ROOT"); root != "" {
		return filepath.Join(root, "scripts", "validate-schema.mjs"), nil
	}
	// REPO_ROOT: standard repo root env var.
	if root := os.Getenv("REPO_ROOT"); root != "" {
		return filepath.Join(root, "enterprise", "platform", "dashboard", "scripts", "validate-schema.mjs"), nil
	}
	// Heuristic: the test binary runs from core/gibson/; go up 3 dirs to repo root.
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("shape_validator: could not determine working directory: %w", err)
	}
	candidate := filepath.Join(cwd, "..", "..", "..", "enterprise", "platform", "dashboard", "scripts", "validate-schema.mjs")
	if _, statErr := os.Stat(candidate); os.IsNotExist(statErr) {
		return "", fmt.Errorf("shape_validator: validate-schema.mjs not found at %s — set REPO_ROOT env var", candidate)
	}
	return candidate, nil
}

// NewShapeValidator starts the Node.js validate-schema process and returns a
// ready-to-use ShapeValidator.
//
// Call Close() when the test suite finishes to terminate the subprocess.
//
// Returns an error if node is not installed or the script fails to start.
func NewShapeValidator() (*ShapeValidator, error) {
	scriptPath, err := nodeScriptPath()
	if err != nil {
		return nil, err
	}

	// Verify node is available.
	if _, lookErr := exec.LookPath("node"); lookErr != nil {
		return nil, fmt.Errorf("shape_validator: node not found in PATH — install Node.js to enable shape validation")
	}

	cmd := exec.Command("node", "--input-type=module", scriptPath) //nolint:gosec // controlled path
	cmd.Stderr = os.Stderr // forward stderr (includes "ready" signal)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("shape_validator: stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("shape_validator: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("shape_validator: start node: %w", err)
	}

	sv := &ShapeValidator{
		cmd:     cmd,
		stdin:   stdinPipe,
		stdout:  bufio.NewScanner(stdoutPipe),
		pending: make(map[string]chan validateResponse),
	}

	// Start the read loop in a goroutine.
	go sv.readLoop()

	// Give the process a moment to emit its "ready" signal on stderr.
	time.Sleep(200 * time.Millisecond)

	return sv, nil
}

// readLoop reads newline-delimited JSON responses from the Node.js process
// and dispatches them to waiting callers via the pending channel map.
func (sv *ShapeValidator) readLoop() {
	for sv.stdout.Scan() {
		line := sv.stdout.Text()
		if line == "" {
			continue
		}
		var resp validateResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			// Ignore malformed output lines (e.g., debug prints).
			continue
		}
		sv.mu.Lock()
		ch, ok := sv.pending[resp.ID]
		if ok {
			delete(sv.pending, resp.ID)
		}
		sv.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}

// Validate checks a JSON body against a Zod schema referenced by schemaRef.
//
// schemaRef format: "src/lib/schemas/missions.ts:ListMissionsResponse"
// (relative to the dashboard root, colon-separated from the export name).
//
// If schemaRef is empty, validation is skipped and nil is returned.
//
// The call blocks until the Node.js process responds or ctx is cancelled.
//
// Requirements: R1.3.
func (sv *ShapeValidator) Validate(ctx context.Context, schemaRef string, body []byte) error {
	if schemaRef == "" {
		return nil // no schema configured — skip
	}

	id := fmt.Sprintf("%d", sv.seq.Add(1))
	req := validateRequest{
		ID:        id,
		SchemaRef: schemaRef,
		Body:      string(body),
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("shape_validator: marshal request: %w", err)
	}

	respCh := make(chan validateResponse, 1)

	sv.mu.Lock()
	if sv.closed {
		sv.mu.Unlock()
		return fmt.Errorf("shape_validator: Validate called on closed validator")
	}
	sv.pending[id] = respCh
	_, writeErr := fmt.Fprintf(sv.stdin, "%s\n", reqJSON)
	sv.mu.Unlock()

	if writeErr != nil {
		sv.mu.Lock()
		delete(sv.pending, id)
		sv.mu.Unlock()
		return fmt.Errorf("shape_validator: write request: %w", writeErr)
	}

	select {
	case resp := <-respCh:
		if !resp.OK {
			return fmt.Errorf("shape_validator: %s", resp.Error)
		}
		return nil
	case <-ctx.Done():
		sv.mu.Lock()
		delete(sv.pending, id)
		sv.mu.Unlock()
		return fmt.Errorf("shape_validator: context cancelled waiting for response for schema %q", schemaRef)
	case <-time.After(10 * time.Second):
		sv.mu.Lock()
		delete(sv.pending, id)
		sv.mu.Unlock()
		return fmt.Errorf("shape_validator: timeout waiting for Zod validation of schema %q", schemaRef)
	}
}

// Close terminates the Node.js subprocess and releases resources.
// Idempotent.
func (sv *ShapeValidator) Close() error {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if sv.closed {
		return nil
	}
	sv.closed = true
	// Send shutdown sentinel.
	_, _ = fmt.Fprintf(sv.stdin, `{"op":"shutdown"}`+"\n")
	_ = sv.stdin.Close()
	// Wait up to 3 seconds for the process to exit.
	done := make(chan error, 1)
	go func() { done <- sv.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = sv.cmd.Process.Kill()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Package-level convenience: Validate (for simple single-call use cases)
// ---------------------------------------------------------------------------

// Validate is a package-level convenience function that starts a fresh
// ShapeValidator, validates the payload, then closes the validator.
//
// For multiple validations in a test suite, prefer creating a shared
// ShapeValidator with NewShapeValidator and calling Close at the end.
//
// Requirements: R1.3.
func ValidateShape(ctx context.Context, schemaRef string, body []byte) error {
	sv, err := NewShapeValidator()
	if err != nil {
		return fmt.Errorf("ValidateShape: create validator: %w", err)
	}
	defer sv.Close() //nolint:errcheck // best-effort cleanup
	return sv.Validate(ctx, schemaRef, body)
}
