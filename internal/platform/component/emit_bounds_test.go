// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// countingFindingSubmitter records every finding that reaches it, so a test can
// assert that a rejected emit left no partial state behind.
type countingFindingSubmitter struct {
	submitted []string
}

func (s *countingFindingSubmitter) Submit(_ context.Context, _, _, findingJSON, _, _ string) (string, error) {
	s.submitted = append(s.submitted, findingJSON)
	return "finding-1", nil
}

// ownEveryWorkItem is a WorkContextRegistry that reports the calling tenant as
// the owner of every work id. Ownership is not what these tests are about — the
// bounds are — so it is stubbed to always resolve, which keeps a failure here
// unambiguously a bounds failure.
type ownEveryWorkItem struct{ tenant string }

func (ownEveryWorkItem) RegisterWorkContext(context.Context, string, string, string) error {
	return nil
}

func (o ownEveryWorkItem) WorkOwner(context.Context, string) (string, error) {
	return o.tenant, nil
}

func boundedComponentServer(submitter FindingSubmitter) *ComponentServiceServer {
	return &ComponentServiceServer{
		logger:           slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		findingSubmitter: submitter,
		workContext:      ownEveryWorkItem{tenant: "test-tenant"},
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// findingJSONOfSize returns a valid finding payload of exactly n bytes.
func findingJSONOfSize(t *testing.T, n int) []byte {
	t.Helper()
	const wrapper = len(`{"title":""}`)
	if n < wrapper {
		t.Fatalf("cannot build a finding of %d bytes", n)
	}
	payload := []byte(`{"title":"` + strings.Repeat("x", n-wrapper) + `"}`)
	if len(payload) != n {
		t.Fatalf("built payload of %d bytes, want %d", len(payload), n)
	}
	return payload
}

// TestComponentSubmitFindingRejectsOverSizePayload is the truncation test for
// the remote-component ingress: an over-limit payload must be refused whole and
// must never reach the submitter, in full or shortened.
func TestComponentSubmitFindingRejectsOverSizePayload(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{
			WorkId:  "work-1",
			Finding: findingJSONOfSize(t, emitbounds.MaxPayloadBytes),
		})
		if err != nil {
			t.Fatalf("finding of exactly MaxPayloadBytes rejected: %v", err)
		}
		if len(submitter.submitted) != 1 {
			t.Fatalf("submitter saw %d findings, want 1", len(submitter.submitted))
		}
	})

	t.Run("one byte over is rejected and nothing is submitted", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{
			WorkId:  "work-1",
			Finding: findingJSONOfSize(t, emitbounds.MaxPayloadBytes+1),
		})
		if err == nil {
			t.Fatal("finding of MaxPayloadBytes+1 accepted; want rejection")
		}
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Errorf("status code = %v, want InvalidArgument", got)
		}
		if !strings.Contains(err.Error(), emitbounds.LimitPayloadBytes) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(submitter.submitted) != 0 {
			t.Fatalf("submitter saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(submitter.submitted))
		}
	})

	t.Run("nothing shortened is submitted", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		oversize := findingJSONOfSize(t, emitbounds.MaxPayloadBytes*2)
		_, _ = svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{
			WorkId:  "work-1",
			Finding: oversize,
		})
		for _, got := range submitter.submitted {
			if len(got) < len(oversize) {
				t.Fatal("a shortened copy was submitted; over-limit input must be rejected, never truncated")
			}
			t.Fatal("an over-limit finding was submitted at all")
		}
	})
}

// TestComponentSubmitFindingRejectsOverCountProperties covers the property caps
// on the free-form maps inside a remote component's finding JSON.
func TestComponentSubmitFindingRejectsOverCountProperties(t *testing.T) {
	metadataWith := func(n int) []byte {
		metadata := make(map[string]any, n)
		for i := range n {
			metadata["k"+itoa(i)] = i
		}
		payload, err := json.Marshal(map[string]any{"title": "props", "metadata": metadata})
		if err != nil {
			panic(err)
		}
		return payload
	}

	t.Run("at the limit is accepted", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{
			WorkId:  "work-1",
			Finding: metadataWith(emitbounds.MaxProperties),
		})
		if err != nil {
			t.Fatalf("finding with exactly MaxProperties metadata keys rejected: %v", err)
		}
		if len(submitter.submitted) != 1 {
			t.Fatalf("submitter saw %d findings, want 1", len(submitter.submitted))
		}
	})

	t.Run("one property over is rejected and nothing is submitted", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{
			WorkId:  "work-1",
			Finding: metadataWith(emitbounds.MaxProperties + 1),
		})
		if err == nil {
			t.Fatal("finding with MaxProperties+1 metadata keys accepted; want rejection")
		}
		if !strings.Contains(err.Error(), emitbounds.LimitProperties) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(submitter.submitted) != 0 {
			t.Fatalf("submitter saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(submitter.submitted))
		}
	})

	t.Run("an over-long property key is rejected", func(t *testing.T) {
		submitter := &countingFindingSubmitter{}
		svc := boundedComponentServer(submitter)

		payload, marshalErr := json.Marshal(map[string]any{
			"metadata": map[string]any{strings.Repeat("k", emitbounds.MaxPropertyKeyBytes+1): 1},
		})
		if marshalErr != nil {
			t.Fatalf("marshal: %v", marshalErr)
		}
		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{WorkId: "work-1", Finding: payload})
		if err == nil {
			t.Fatal("finding with an over-long metadata key accepted; want rejection")
		}
		if !strings.Contains(err.Error(), emitbounds.LimitPropertyKeyBytes) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(submitter.submitted) != 0 {
			t.Fatalf("submitter saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(submitter.submitted))
		}
	})
}

// TestComponentSubmitFindingRejectsOverCountPerWorkItem exercises the per-task
// cap on the work-item-keyed ingress.
func TestComponentSubmitFindingRejectsOverCountPerWorkItem(t *testing.T) {
	submitter := &countingFindingSubmitter{}
	svc := boundedComponentServer(submitter)
	small := []byte(`{"title":"f"}`)

	for i := range emitbounds.MaxObservationsPerTask {
		_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{WorkId: "work-1", Finding: small})
		if err != nil {
			t.Fatalf("finding %d of MaxObservationsPerTask rejected: %v", i+1, err)
		}
	}
	if len(submitter.submitted) != emitbounds.MaxObservationsPerTask {
		t.Fatalf("submitter saw %d findings, want %d", len(submitter.submitted), emitbounds.MaxObservationsPerTask)
	}

	_, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{WorkId: "work-1", Finding: small})
	if err == nil {
		t.Fatal("finding MaxObservationsPerTask+1 accepted; want rejection")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Errorf("status code = %v, want ResourceExhausted", got)
	}
	if len(submitter.submitted) != emitbounds.MaxObservationsPerTask {
		t.Fatalf("submitter saw %d findings after the over-limit emit; a rejected emit must write nothing",
			len(submitter.submitted))
	}

	// A second work item gets its own budget.
	if _, err := svc.SubmitFinding(tenantCtx(), &componentpb.SubmitFindingRequest{WorkId: "work-2", Finding: small}); err != nil {
		t.Fatalf("a second work item was charged against the first one's budget: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
