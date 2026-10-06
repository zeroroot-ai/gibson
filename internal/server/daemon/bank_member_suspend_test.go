// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/bank"
)

// fakeSuspender records each suspend and resume.
type fakeSuspender struct{ calls []string }

func (f *fakeSuspender) Suspend(_ context.Context, tenant, sandboxID string) error {
	f.calls = append(f.calls, "suspend "+tenant+" "+sandboxID)
	return nil
}

func (f *fakeSuspender) Resume(_ context.Context, tenant, sandboxID string) error {
	f.calls = append(f.calls, "resume "+tenant+" "+sandboxID)
	return nil
}

// The member launcher suspends and resumes the sandbox of a member through
// the setec suspender, and refuses with no suspender or no sandbox.
func TestMemberLauncher_SuspendAndResume(t *testing.T) {
	ctx := context.Background()
	m := &bank.Member{ID: "m-1", SandboxID: "sbx-1"}
	s := &fakeSuspender{}
	l := &memberLauncher{daemon: &daemonImpl{sandboxSuspender: s}}
	if err := l.SuspendMember(ctx, "acme", m); err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}
	if err := l.ResumeMember(ctx, "acme", m); err != nil {
		t.Fatalf("ResumeMember: %v", err)
	}
	if len(s.calls) != 2 || s.calls[0] != "suspend acme sbx-1" || s.calls[1] != "resume acme sbx-1" {
		t.Errorf("calls = %v", s.calls)
	}

	none := &memberLauncher{daemon: &daemonImpl{}}
	if err := none.SuspendMember(ctx, "acme", m); err == nil {
		t.Error("a suspend with no suspender was accepted")
	}
	if err := l.ResumeMember(ctx, "acme", &bank.Member{ID: "m-2"}); err == nil {
		t.Error("a resume of a member with no sandbox was accepted")
	}
}
