// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"errors"
	"testing"
	"time"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

func validSpec() *jobpb.JobSpec {
	return &jobpb.JobSpec{
		Goal: "fix the CVE",
		Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab", Project: "group/app",
			Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST,
		}},
		CredentialNames: []string{"gitlab-token"},
		Acceptance: &jobpb.Acceptance{
			VerifierComponent: "agent/verifier", PassingScore: 0.8, MaxPasses: 3,
		},
	}
}

func TestValidateSpec_AcceptsAWorkableSpec(t *testing.T) {
	if err := ValidateSpec(validSpec()); err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	// A goal on its own is a chat turn, which is a job with only a goal.
	if err := ValidateSpec(&jobpb.JobSpec{Goal: "what changed today?"}); err != nil {
		t.Fatalf("a goal alone must be enough: %v", err)
	}
	// A repository on its own is enough too: the work is named by the
	// deliverable rather than by prose.
	if err := ValidateSpec(&jobpb.JobSpec{Repositories: []*jobpb.RepositorySpec{{
		Name: "app", ConnectorRef: "connector/gitlab", Project: "g/a",
		Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE,
	}}}); err != nil {
		t.Fatalf("a repository alone must be enough: %v", err)
	}
}

func TestValidateSpec_Refusals(t *testing.T) {
	cases := map[string]*jobpb.JobSpec{
		"nil spec":                  nil,
		"no goal and no repository": {},
		"repository with no name": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			ConnectorRef: "connector/gitlab", Project: "g/a",
			Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE,
		}}},
		"repository with no connector": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			Name: "app", Project: "g/a", Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE,
		}}},
		"repository with no project": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab",
			Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE,
		}}},
		"repository with no deliverable": {Goal: "x", Repositories: []*jobpb.RepositorySpec{{
			Name: "app", ConnectorRef: "connector/gitlab", Project: "g/a",
		}}},
		"two repositories with one name": {Goal: "x", Repositories: []*jobpb.RepositorySpec{
			{Name: "app", ConnectorRef: "c/g", Project: "g/a", Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE},
			{Name: "app", ConnectorRef: "c/g", Project: "g/b", Deliverable: jobpb.DeliverableKind_DELIVERABLE_KIND_NONE},
		}},
		"empty credential name":   {Goal: "x", CredentialNames: []string{""}},
		"score above one":         {Goal: "x", Acceptance: &jobpb.Acceptance{PassingScore: 1.1}},
		"score below zero":        {Goal: "x", Acceptance: &jobpb.Acceptance{PassingScore: -0.1}},
		"negative max passes":     {Goal: "x", Acceptance: &jobpb.Acceptance{MaxPasses: -1}},
		"passes with no verifier": {Goal: "x", Acceptance: &jobpb.Acceptance{MaxPasses: 3}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSpec(spec); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestOpenInput_Validate(t *testing.T) {
	good := OpenInput{BankID: "b1", Spec: validSpec(), OpenedBy: Principal{Kind: PrincipalUser, ID: "alice"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for name, mutate := range map[string]func(*OpenInput){
		"no bank":         func(in *OpenInput) { in.BankID = " " },
		"no opener kind":  func(in *OpenInput) { in.OpenedBy.Kind = "" },
		"unknown kind":    func(in *OpenInput) { in.OpenedBy.Kind = "robot" },
		"no opener id":    func(in *OpenInput) { in.OpenedBy.ID = "" },
		"unworkable spec": func(in *OpenInput) { in.Spec = &jobpb.JobSpec{} },
	} {
		t.Run(name, func(t *testing.T) {
			in := OpenInput{BankID: "b1", Spec: validSpec(), OpenedBy: Principal{Kind: PrincipalUser, ID: "alice"}}
			mutate(&in)
			if err := in.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSendInput_Validate_DefaultsToATurn(t *testing.T) {
	in := SendInput{JobID: "j1", Message: "go on", Sender: Principal{Kind: PrincipalUser, ID: "alice"}}
	if err := in.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if in.Kind != InputTurn {
		t.Errorf("kind = %q, want turn", in.Kind)
	}
}

func TestSendInput_Validate_Refusals(t *testing.T) {
	for name, in := range map[string]SendInput{
		"no job":       {Message: "x", Sender: Principal{Kind: PrincipalUser, ID: "a"}},
		"no message":   {JobID: "j", Sender: Principal{Kind: PrincipalUser, ID: "a"}},
		"unknown kind": {JobID: "j", Message: "x", Kind: "shout", Sender: Principal{Kind: PrincipalUser, ID: "a"}},
		"no sender":    {JobID: "j", Message: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			input := in
			if err := input.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCloseInput_Validate(t *testing.T) {
	good := CloseInput{JobID: "j1", Verdict: VerdictAccomplished, Score: 0.9,
		Closer: Principal{Kind: PrincipalComponent, ID: "agent_principal:node"}}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for name, in := range map[string]CloseInput{
		"no job":           {Verdict: VerdictFailed, Closer: Principal{Kind: PrincipalUser, ID: "a"}},
		"no verdict":       {JobID: "j", Closer: Principal{Kind: PrincipalUser, ID: "a"}},
		"unknown verdict":  {JobID: "j", Verdict: "maybe", Closer: Principal{Kind: PrincipalUser, ID: "a"}},
		"score above one":  {JobID: "j", Verdict: VerdictFailed, Score: 1.5, Closer: Principal{Kind: PrincipalUser, ID: "a"}},
		"score below zero": {JobID: "j", Verdict: VerdictFailed, Score: -1, Closer: Principal{Kind: PrincipalUser, ID: "a"}},
		"no closer":        {JobID: "j", Verdict: VerdictFailed},
	} {
		t.Run(name, func(t *testing.T) {
			input := in
			if err := input.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestStateAndVerdictHelpers(t *testing.T) {
	for _, s := range []State{StateOpen, StateWorking, StateWaiting, StateClosed} {
		if !IsState(s) {
			t.Errorf("%q must be a state", s)
		}
	}
	if IsState("paused") {
		t.Error("paused is not a state")
	}
	for _, v := range []Verdict{VerdictAccomplished, VerdictFailed, VerdictAbandoned} {
		if !IsVerdict(v) {
			t.Errorf("%q must be a verdict", v)
		}
	}
	if IsVerdict("") || IsVerdict("maybe") {
		t.Error("only the three verdicts are verdicts")
	}
	for _, k := range []InputKind{InputTurn, InputAnswer, InputWrapUp} {
		if !IsInputKind(k) {
			t.Errorf("%q must be an input kind", k)
		}
	}
	if IsInputKind("shout") {
		t.Error("shout is not an input kind")
	}
}

func TestClampPageSize(t *testing.T) {
	if got := clampPageSize(0); got != DefaultPageSize {
		t.Errorf("0 -> %d", got)
	}
	if got := clampPageSize(-1); got != DefaultPageSize {
		t.Errorf("negative -> %d", got)
	}
	if got := clampPageSize(MaxPageSize + 100); got != MaxPageSize {
		t.Errorf("above the maximum -> %d, want it capped", got)
	}
	if got := clampPageSize(7); got != 7 {
		t.Errorf("7 -> %d", got)
	}
}

func TestPageToken_RoundTripsAndRefusesGarbage(t *testing.T) {
	at := time.Date(2026, 9, 1, 10, 30, 0, 42, time.UTC)
	token := encodeToken(cursor{at: &at, id: "job-9"})
	got, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken: %v", err)
	}
	if got.id != "job-9" || !got.at.Equal(at) {
		t.Fatalf("cursor = %+v", got)
	}
	if encodeToken(cursor{}) != "" {
		t.Error("a cursor with no time encodes to no token")
	}
	if c, err := decodeToken(""); err != nil || c.at != nil {
		t.Errorf("an empty token starts at the newest: %+v %v", c, err)
	}
	for _, bad := range []string{"!!!", "bm90aGluZw"} {
		if _, err := decodeToken(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("decodeToken(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestTrimPage(t *testing.T) {
	at := time.Now().UTC()
	rows := []*Job{{ID: "a", OpenedAt: at}, {ID: "b", OpenedAt: at}, {ID: "c", OpenedAt: at}}
	page, next, err := trimPage(rows, 2)
	if err != nil || len(page) != 2 || next == "" {
		t.Fatalf("page = %d next = %q err = %v", len(page), next, err)
	}
	c, err := decodeToken(next)
	if err != nil || c.id != "b" {
		t.Fatalf("token points at %+v, want the last row of the page", c)
	}
	page, next, err = trimPage(rows[:1], 2)
	if err != nil || len(page) != 1 || next != "" {
		t.Fatalf("a short page carries no token: %d %q %v", len(page), next, err)
	}
}

func TestNewPostgresStore_NeedsAPool(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a store with no pool must not be constructible")
		}
	}()
	NewPostgresStore(nil)
}

func TestUnmarshalDeliverables(t *testing.T) {
	got, err := unmarshalDeliverables(nil)
	if err != nil || got != nil {
		t.Fatalf("no bytes means no deliverables: %v %v", got, err)
	}
	got, err = unmarshalDeliverables([]byte(`[{"kind":"DELIVERABLE_KIND_MERGE_REQUEST","ref":"mr-1","url":"https://x/1"}]`))
	if err != nil {
		t.Fatalf("unmarshalDeliverables: %v", err)
	}
	if len(got) != 1 || got[0].GetRef() != "mr-1" ||
		got[0].GetKind() != jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST {
		t.Fatalf("deliverables = %+v", got)
	}
	if _, err := unmarshalDeliverables([]byte(`not json`)); err == nil {
		t.Error("unreadable stored deliverables must be an error, never silently empty")
	}
}
