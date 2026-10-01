// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package jobnode

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// staticFindings answers the same ids for every run.
func staticFindings(ids ...string) FindingsResolver {
	return FindingsResolverFunc(func(_ context.Context, _, _ string) ([]string, error) {
		return ids, nil
	})
}

// TestRun_ResolvesTheFindingsReference is the gibson#497 fixture. ClosedJob.Inputs
// was JobSpec.inputs verbatim and nothing populated it at run time, so a fix job
// could only be correlated to a finding by hand-writing the id into the mission —
// which is a mock, not a run. A mission definition cannot name finding ids,
// because the run is what produces them.
func TestRun_ResolvesTheFindingsReference(t *testing.T) {
	obs := &recordingObserver{}
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Closed = obs
	in.Findings = staticFindings("finding-b", "finding-a")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(obs.got) != 1 {
		t.Fatalf("observer calls = %d, want 1", len(obs.got))
	}
	got := obs.got[0].Inputs
	// Sorted, so one run against the same World always opens the same job.
	if len(got) != 2 || got[0] != "finding-a" || got[1] != "finding-b" {
		t.Errorf("inputs = %v, want the resolved finding ids in sorted order", got)
	}
	for _, in := range got {
		if strings.Contains(in, "{{") {
			t.Errorf("a reference reached the close: %q", in)
		}
	}
}

// The job must be OPENED with the resolved inputs too, not only closed with them:
// the member reads its inputs from the job it took.
func TestRun_OpensTheJobWithTheResolvedInputs(t *testing.T) {
	jobs := mergeRequestJobs()
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(jobs, &scriptedVerifier{}, s)
	in.Findings = staticFindings("finding-a")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(jobs.opened) != 1 {
		t.Fatalf("opens = %d", len(jobs.opened))
	}
	got := jobs.opened[0].Spec.GetInputs()
	if len(got) != 1 || got[0] != "finding-a" {
		t.Errorf("opened with inputs %v, want the resolved id", got)
	}
}

// A literal id and a reference mix, and the literals keep their declared order.
func TestRun_LiteralInputsSurviveAlongsideTheReference(t *testing.T) {
	obs := &recordingObserver{}
	s := spec(1, "")
	s.Inputs = []string{"plan-1", FindingsOpen, "plan-2"}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Closed = obs
	in.Findings = staticFindings("finding-a")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got := obs.got[0].Inputs
	want := []string{"plan-1", "finding-a", "plan-2"}
	if len(got) != len(want) {
		t.Fatalf("inputs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("inputs = %v, want %v", got, want)
		}
	}
}

// A target with nothing open is a target with nothing to fix. The job runs and
// closes having linked nothing, which is the honest outcome — not an error.
func TestRun_NoOpenFindingsOpensAJobWithNoInputs(t *testing.T) {
	obs := &recordingObserver{}
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Closed = obs
	in.Findings = staticFindings()

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(obs.got) != 1 {
		t.Fatalf("observer calls = %d, want 1", len(obs.got))
	}
	if len(obs.got[0].Inputs) != 0 {
		t.Errorf("inputs = %v, want none", obs.got[0].Inputs)
	}
}

// A reference with no resolver must fail the node. Passing it through was the
// defect: it reached close as a World node id naming nothing, fixedByEvents
// dropped it, and the FIXED_BY edge went missing without a word.
func TestRun_RefusesTheReferenceWithNoResolver(t *testing.T) {
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Findings = nil

	_, err := Run(context.Background(), in)
	if err == nil {
		t.Fatal("a reference with no resolver must fail the node, not resolve to nothing")
	}
	if !strings.Contains(err.Error(), "resolves no findings") {
		t.Errorf("error = %v", err)
	}
}

func TestRun_RefusesAnUnknownReference(t *testing.T) {
	s := spec(1, "")
	s.Inputs = []string{"{{findings.closed}}"}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Findings = staticFindings("finding-a")

	_, err := Run(context.Background(), in)
	if err == nil {
		t.Fatal("an unknown reference must fail rather than reach the job as text")
	}
	for _, want := range []string{"{{findings.closed}}", "unknown input reference", FindingsOpen} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not name %q", err, want)
		}
	}
}

// A resolver that cannot answer fails the node. "Nothing to fix" and "I could not
// find out" must not look the same.
func TestRun_AResolverFailureFailsTheNode(t *testing.T) {
	boom := errors.New("the World has no such mission")
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Findings = FindingsResolverFunc(func(_ context.Context, _, _ string) ([]string, error) {
		return nil, boom
	})

	_, err := Run(context.Background(), in)
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the resolver failure", err)
	}
}

// A spec that names its inputs outright needs no resolver and is untouched.
func TestRun_LiteralInputsNeedNoResolver(t *testing.T) {
	obs := &recordingObserver{}
	s := spec(1, "")
	s.Inputs = []string{"finding-1", "plan-1"}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Closed = obs
	in.Findings = nil

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got := obs.got[0].Inputs
	if len(got) != 2 || got[0] != "finding-1" || got[1] != "plan-1" {
		t.Errorf("inputs = %v, want them unchanged", got)
	}
}

// The resolver may legitimately return the same id twice (two scans, one
// finding). An input list with a duplicate would emit the FIXED_BY edge twice.
func TestRun_DuplicateIdsCollapse(t *testing.T) {
	obs := &recordingObserver{}
	s := spec(1, "")
	s.Inputs = []string{"finding-a", FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Closed = obs
	in.Findings = staticFindings("finding-a", "finding-a", "finding-b")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	got := obs.got[0].Inputs
	if len(got) != 2 {
		t.Errorf("inputs = %v, want each id once", got)
	}
}

// The spec the caller handed in is a template and must stay one: the next run of
// the same node resolves against the World as it is then.
func TestRun_DoesNotModifyTheCallersSpec(t *testing.T) {
	s := spec(1, "")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), &scriptedVerifier{}, s)
	in.Findings = staticFindings("finding-a")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(s.Inputs) != 1 || s.Inputs[0] != FindingsOpen {
		t.Errorf("the caller's spec was rewritten: %v", s.Inputs)
	}
}

// The verifier judges the work against the inputs the job actually holds. It read
// the stamped copy while the close read the unstamped one, so a resolution
// applied to one would have been invisible to the other.
func TestRun_TheVerifierSeesTheResolvedInputs(t *testing.T) {
	v := &scriptedVerifier{reports: []Report{{Pass: true, Score: 1}}}
	s := spec(1, "tool/verify")
	s.Inputs = []string{FindingsOpen}
	in := input(mergeRequestJobs(), v, s)
	in.Findings = staticFindings("finding-a")

	if _, err := Run(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(v.payloads) != 1 {
		t.Fatalf("verify calls = %d", len(v.payloads))
	}
	got := v.payloads[0].Inputs
	if len(got) != 1 || got[0] != "finding-a" {
		t.Errorf("the verifier saw inputs %v, want the resolved id", got)
	}
}
