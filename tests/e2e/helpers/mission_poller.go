//go:build e2e
// +build e2e

// Package helpers — mission_poller.go
//
// Polls mission state and findings via the daemon gRPC client and HTTP API.
// Complementary to the event stream (events for liveness, store for canonical truth).
//
// Design Component 3 / Requirements: R1.6, R1.7, R1.8.
package helpers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
)

// MissionFinding is the typed finding record returned by the findings API.
// Fields map to gibson.types.v1.Finding required fields (R1.8).
type MissionFinding struct {
	ID          string `json:"id"`
	MissionID   string `json:"mission_id"`
	CreatedAt   string `json:"created_at"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"` // present when mock-LLM path exercised (R3.3)
	Title       string `json:"title"`
}

// missionFindingsAPIResponse is the JSON shape returned by
// /api/tenant/<slug>/mission/<id>/findings.
// The server may return either { findings: [...] } or { data: [...] } or
// a flat array — we handle all three.
type missionFindingsAPIResponse struct {
	Findings []MissionFinding `json:"findings"`
	Data     []MissionFinding `json:"data"`
}

// ErrMissionStateTimeout is returned when WaitForMissionState deadline elapses.
var ErrMissionStateTimeout = fmt.Errorf("mission_poller: deadline exceeded waiting for mission state")

// WaitForMissionState polls the daemon until the mission reaches the expected
// state (e.g., "completed", "failed") or the deadline elapses.
//
// Polls via ListMissions — filtering by the mission ID (exact status match or
// substring). No raw time.Sleep: uses context deadline + exponential backoff.
//
// Requirements: R1.6.
func WaitForMissionState(
	ctx context.Context,
	client daemonpb.DaemonServiceClient,
	missionID string,
	wantState string,
	deadline time.Duration,
) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	backoff := 500 * time.Millisecond
	const maxBackoff = 5 * time.Second
	startTime := time.Now()

	for {
		// Check context before polling.
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf(
				"%w: waited %s for mission %s to reach state %q (last check: %.1fs ago)",
				ErrMissionStateTimeout, deadline, missionID, wantState, time.Since(startTime).Seconds(),
			)
		default:
		}

		// Fetch mission list and find the target mission.
		resp, err := client.ListMissions(deadlineCtx, &daemonpb.ListMissionsRequest{
			ActiveOnly: false,
			Limit:      100,
		})
		if err != nil {
			// Transient error — retry after backoff.
			timer := time.NewTimer(backoff)
			select {
			case <-deadlineCtx.Done():
				timer.Stop()
				return fmt.Errorf("%w: ListMissions error: %v", ErrMissionStateTimeout, err)
			case <-timer.C:
			}
			backoff = minDuration(backoff*2, maxBackoff)
			continue
		}

		for _, m := range resp.GetMissions() {
			if m.GetId() != missionID {
				continue
			}
			status := strings.ToLower(m.GetStatus())
			want := strings.ToLower(wantState)
			if status == want || strings.Contains(status, want) {
				return nil // reached desired state
			}
			break
		}

		// Wait before next poll — deadline-bounded.
		timer := time.NewTimer(backoff)
		select {
		case <-deadlineCtx.Done():
			timer.Stop()
			return fmt.Errorf(
				"%w: waited %s for mission %s to reach state %q",
				ErrMissionStateTimeout, deadline, missionID, wantState,
			)
		case <-timer.C:
		}
		backoff = minDuration(backoff*2, maxBackoff)
	}
}

// GetMissionFindings fetches the findings for a mission via the HTTP API:
//   GET /api/tenant/<slug>/mission/<missionID>/findings
//
// Returns the parsed finding slice. Returns nil (not an error) if the server
// returns an explicit empty-findings terminal record (per R1.7: never null/missing).
//
// Requirements: R1.7, R1.8.
func GetMissionFindings(
	ctx context.Context,
	cookies []*PlaywrightCookie,
	baseURL string,
	slug string,
	missionID string,
) ([]MissionFinding, error) {
	path := fmt.Sprintf("/api/tenant/%s/mission/%s/findings", slug, missionID)
	rawBody, err := FetchProtectedJSON(ctx, cookies, baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("mission_poller: GetMissionFindings: fetch %s: %w", path, err)
	}

	// The findings API may return a flat array, { findings: [...] }, or { data: [...] }.
	// Try flat array first.
	var flatFindings []MissionFinding
	if jsonErr := json.Unmarshal(rawBody, &flatFindings); jsonErr == nil {
		return flatFindings, nil
	}

	// Try { findings: [...] } or { data: [...] }.
	var wrapped missionFindingsAPIResponse
	if jsonErr := json.Unmarshal(rawBody, &wrapped); jsonErr != nil {
		return nil, fmt.Errorf(
			"mission_poller: GetMissionFindings: unmarshal response from %s: %w (body: %.200s)",
			path, jsonErr, string(rawBody),
		)
	}
	if len(wrapped.Findings) > 0 {
		return wrapped.Findings, nil
	}
	return wrapped.Data, nil
}

// GetMissionFindingsHTTP fetches findings directly without a cookie jar —
// useful when the test is operating against the daemon's internal port.
// Falls back to GetMissionFindings with provided cookies if those are non-nil.
//
// Requirements: R1.7, R1.8.
func GetMissionFindingsHTTP(
	ctx context.Context,
	baseURL string,
	slug string,
	missionID string,
) ([]MissionFinding, error) {
	reqURL := strings.TrimRight(baseURL, "/") +
		fmt.Sprintf("/api/tenant/%s/mission/%s/findings", slug, missionID)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Kind dev only
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("mission_poller: GetMissionFindingsHTTP: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mission_poller: GetMissionFindingsHTTP: GET %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"mission_poller: GetMissionFindingsHTTP: GET %s returned HTTP %d (body: %.200s)",
			reqURL, resp.StatusCode, string(rawBody),
		)
	}

	// Same deserialization as GetMissionFindings.
	var flatFindings []MissionFinding
	if jsonErr := json.Unmarshal(rawBody, &flatFindings); jsonErr == nil {
		return flatFindings, nil
	}
	var wrapped missionFindingsAPIResponse
	if jsonErr := json.Unmarshal(rawBody, &wrapped); jsonErr != nil {
		return nil, fmt.Errorf(
			"mission_poller: GetMissionFindingsHTTP: unmarshal response: %w (body: %.200s)",
			jsonErr, string(rawBody),
		)
	}
	if len(wrapped.Findings) > 0 {
		return wrapped.Findings, nil
	}
	return wrapped.Data, nil
}

// AssertFindingFields asserts that each finding in the slice has the required
// fields per gibson.types.v1.Finding (R1.8):
//   - id (non-empty)
//   - mission_id (matches the expected mission ID)
//   - created_at (non-empty)
//   - severity (non-empty)
//   - description (non-empty)
//
// Requirements: R1.8.
func AssertFindingFields(t *testing.T, findings []MissionFinding, missionID string) {
	t.Helper()
	for i, f := range findings {
		if f.ID == "" {
			t.Errorf("mission_poller: finding[%d]: id is empty (R1.8: id is required)", i)
		}
		if f.MissionID != missionID {
			t.Errorf("mission_poller: finding[%d]: mission_id=%q expected %q (R1.8: must match)", i, f.MissionID, missionID)
		}
		if f.CreatedAt == "" {
			t.Errorf("mission_poller: finding[%d]: created_at is empty (R1.8: required)", i)
		}
		if f.Severity == "" {
			t.Errorf("mission_poller: finding[%d]: severity is empty (R1.8: required)", i)
		}
		if f.Description == "" {
			t.Errorf("mission_poller: finding[%d]: description is empty (R1.8: required)", i)
		}
	}
}

// AssertFindingsNotNil asserts that the findings response is not nil/missing
// per R1.7: either at least one finding OR an explicit empty slice is acceptable
// — but a nil/null JSON response is never acceptable.
//
// Requirements: R1.7.
func AssertFindingsNotNil(t *testing.T, findings []MissionFinding, missionID string) {
	t.Helper()
	// findings == nil means the API returned null or an unparseable response.
	// findings == []MissionFinding{} (empty slice) is acceptable per R1.7.
	if findings == nil {
		t.Errorf(
			"mission_poller: GetMissionFindings returned nil for mission %s "+
				"(R1.7: null/missing findings response is never acceptable — "+
				"expected at least an explicit empty slice [] or finding objects). "+
				"MISSION-B catalog: Candidate C — SubmitFinding writes to Redis but "+
				"GraphRAG bridge async store may be failing silently.",
			missionID,
		)
	}
}

// PrintMissionDiagnostic logs the mission status, last events, and finding count
// for the failure diagnostic dump (NFR Usability).
//
// Requirements: NFR Usability.
func PrintMissionDiagnostic(
	t *testing.T,
	ctx context.Context,
	client daemonpb.DaemonServiceClient,
	missionID string,
	lastEvents []MissionEvent,
	findings []MissionFinding,
) {
	t.Helper()
	t.Logf("=== MISSION DIAGNOSTIC for %s ===", missionID)

	// Mission status from store.
	resp, err := client.ListMissions(ctx, &daemonpb.ListMissionsRequest{
		ActiveOnly: false,
		Limit:      100,
	})
	if err != nil {
		t.Logf("  mission_poller: ListMissions error: %v", err)
	} else {
		for _, m := range resp.GetMissions() {
			if m.GetId() == missionID {
				t.Logf("  mission status: %s findings_count: %d", m.GetStatus(), m.GetFindingCount())
				break
			}
		}
	}

	// Last 5 events.
	t.Logf("  last %d event(s) from stream:", min5(len(lastEvents)))
	for i, e := range lastEvents {
		if i >= 5 {
			break
		}
		t.Logf("    [%d] %s", i, e.String())
	}

	// Finding count.
	t.Logf("  findings from API: %d", len(findings))
	t.Logf("=== END MISSION DIAGNOSTIC ===")
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func min5(n int) int {
	if n < 5 {
		return n
	}
	return 5
}
