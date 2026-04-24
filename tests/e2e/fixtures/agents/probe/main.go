// probe — deterministic e2e test agent.
//
// This binary is ONLY for use in the mission-run-e2e-tdd test suite.
// It exercises the full agent lifecycle deterministically:
//
//	Register → PollWork (loop) → Complete (LLM) → SubmitFinding → terminate
//
// Environment variables:
//
//	GIBSON_DAEMON_ADDR    — daemon gRPC address (default: gibson.gibson.svc.cluster.local:50002)
//	GIBSON_TENANT_ID      — tenant ID for authentication
//	GIBSON_API_KEY        — API key for authentication (gsk_-prefixed)
//	PROBE_SEED            — deterministic seed for finding content (default: "e2e-probe-seed-v1")
//	PROBE_WORK_TIMEOUT_MS — PollWork timeout in ms (default: 30000)
//	PROBE_MAX_ITEMS       — maximum work items to process before exiting (default: 1)
//
// Requirements: R2.1, R2.3, R2.4, NFR Security (no external network beyond target).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	defaultDaemonAddr    = "gibson.gibson.svc.cluster.local:50002"
	defaultSeed          = "e2e-probe-seed-v1"
	defaultWorkTimeoutMS = 30_000
	defaultMaxItems      = 1
	agentKind            = "agent"
	agentName            = "probe"
	agentVersion         = "test"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("probe: fatal error", "err", err)
		os.Exit(1)
	}
	slog.Info("probe: work complete — exiting")
}

func run() error {
	// Read configuration from env vars.
	daemonAddr := envOrDefault("GIBSON_DAEMON_ADDR", defaultDaemonAddr)
	tenantID := os.Getenv("GIBSON_TENANT_ID")
	apiKey := os.Getenv("GIBSON_API_KEY")
	seed := envOrDefault("PROBE_SEED", defaultSeed)
	maxItems := envIntOrDefault("PROBE_MAX_ITEMS", defaultMaxItems)
	workTimeoutMS := envIntOrDefault("PROBE_WORK_TIMEOUT_MS", defaultWorkTimeoutMS)

	slog.Info("probe: starting", "addr", daemonAddr, "seed", seed, "max_items", maxItems)

	// Connect to the daemon.
	conn, err := grpc.NewClient(
		daemonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("probe: dial daemon %s: %w", daemonAddr, err)
	}
	defer conn.Close()

	client := componentpb.NewComponentServiceClient(conn)

	// Build gRPC metadata for authentication.
	md := metadata.New(map[string]string{})
	if tenantID != "" {
		md.Set("x-tenant-id", tenantID)
	}
	if apiKey != "" {
		md.Set("authorization", "Bearer "+apiKey)
	}
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Register with the daemon's component registry.
	registerCtx, registerCancel := context.WithTimeout(ctx, 30*time.Second)
	defer registerCancel()

	regResp, err := client.RegisterComponent(registerCtx, &componentpb.RegisterComponentRequest{
		Kind:    agentKind,
		Name:    agentName,
		Version: agentVersion,
		Metadata: map[string]string{
			"e2e_only": "true",
			"seed":     seed,
		},
		Capabilities: []string{"llm_complete", "submit_finding"},
	})
	if err != nil {
		return fmt.Errorf("probe: RegisterComponent: %w", err)
	}
	instanceID := regResp.GetInstanceId()
	slog.Info("probe: registered", "instance_id", instanceID)

	// Work loop: poll for work items, process each deterministically.
	processed := 0
	for processed < maxItems {
		// PollWork with timeout.
		pollCtx, pollCancel := context.WithTimeout(ctx, time.Duration(workTimeoutMS)*time.Millisecond+5*time.Second)

		workResp, pollErr := client.PollWork(pollCtx, &componentpb.PollWorkRequest{
			InstanceId: instanceID,
			TimeoutMs:  int32(workTimeoutMS),
		})
		pollCancel()

		if pollErr != nil {
			return fmt.Errorf("probe: PollWork (item %d): %w", processed+1, pollErr)
		}

		workID := workResp.GetWorkId()
		if workID == "" {
			// No work available — this is fine for the first poll after deploy.
			// The orchestrator will dispatch work when a mission runs.
			slog.Info("probe: no work available — waiting for mission dispatch")
			// Brief pause before re-polling (bounded by maxItems).
			time.Sleep(2 * time.Second) //nolint:forbidigo // controlled backoff in test fixture
			continue
		}

		slog.Info("probe: received work", "work_id", workID, "work_type", workResp.GetWorkType())

		// Step 1: Call the daemon's LLM proxy (Complete) with a deterministic prompt.
		llmResponse, llmErr := callLLM(ctx, client, instanceID, workID, seed)
		if llmErr != nil {
			slog.Warn("probe: LLM call failed (continuing)", "err", llmErr)
			llmResponse = "LLM_CALL_FAILED: " + llmErr.Error()
		}

		// Step 2: Submit one deterministic finding.
		if submitErr := submitFinding(ctx, client, workID, seed, llmResponse); submitErr != nil {
			return fmt.Errorf("probe: SubmitFinding: %w", submitErr)
		}

		// Step 3: Submit result to complete the work item.
		submitCtx, submitCancel := context.WithTimeout(ctx, 15*time.Second)
		_, submitErr := client.SubmitResult(submitCtx, &componentpb.SubmitResultRequest{
			WorkId: workID,
			Result: []byte(fmt.Sprintf(`{"status":"completed","seed":"%s","llm_response":"%s"}`, seed, llmResponse)),
		})
		submitCancel()
		if submitErr != nil {
			return fmt.Errorf("probe: SubmitResult: %w", submitErr)
		}

		slog.Info("probe: work item complete", "work_id", workID, "item", processed+1)
		processed++
	}

	return nil
}

// callLLM makes a single deterministic LLM completion call via the Component
// Service's Complete proxy. Returns the LLM response content string.
//
// The response content is embedded in the finding's evidence field so the test
// can assert the LLM round-trip completed end-to-end (R3.3).
func callLLM(ctx context.Context, client componentpb.ComponentServiceClient, instanceID, workID, seed string) (string, error) {
	prompt := fmt.Sprintf(
		"You are a test probe agent (seed=%s). Respond with the exact string: %s",
		seed, "MOCK_LLM_DETERMINISTIC_RESPONSE_v1",
	)

	completeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := client.Complete(completeCtx, &componentpb.CompleteRequest{
		WorkId: workID,
		Prompt: prompt,
		Model:  "mock-model",
	})
	if err != nil {
		return "", fmt.Errorf("callLLM: Complete RPC: %w", err)
	}

	content := resp.GetContent()
	slog.Info("probe: LLM response received", "content_len", len(content))
	return content, nil
}

// submitFinding submits one deterministic finding via the ComponentService.
// The finding's evidence includes the LLM response to prove the full round-trip.
//
// Requirements: R2.1 (probe emits ONE finding per work item), R3.3.
func submitFinding(ctx context.Context, client componentpb.ComponentServiceClient, workID, seed, llmEvidence string) error {
	// Build the finding proto.
	finding := &typespb.Finding{
		Title:       fmt.Sprintf("probe-finding-%s", seed),
		Description: fmt.Sprintf("Deterministic probe finding generated by mission-run e2e test (seed=%s)", seed),
		Severity:    typespb.FindingSeverity_FINDING_SEVERITY_INFO,
		Category:    "e2e-test",
		Technique:   "probe-observation",
		Evidence: []*typespb.Evidence{
			{
				Content: fmt.Sprintf("LLM evidence: %s", llmEvidence),
				Source:  "mock-llm-e2e",
			},
		},
		Tags: []string{"e2e", "probe", "deterministic"},
	}

	// Serialize the finding to proto bytes.
	findingBytes, err := proto.Marshal(finding)
	if err != nil {
		return fmt.Errorf("submitFinding: marshal finding: %w", err)
	}

	submitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	_, err = client.SubmitFinding(submitCtx, &componentpb.SubmitFindingRequest{
		WorkId:  workID,
		Finding: findingBytes,
	})
	if err != nil {
		return fmt.Errorf("submitFinding: SubmitFinding RPC: %w", err)
	}

	slog.Info("probe: finding submitted", "title", finding.GetTitle(), "seed", seed)
	return nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
