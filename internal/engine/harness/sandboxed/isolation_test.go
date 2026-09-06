// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestVerifyIsolation(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		resp      LaunchResponse
		wantErr   bool
	}{
		{
			name:      "no class requested is a denial",
			requested: "",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid"},
			wantErr:   true,
		},
		{
			name:      "class the transport does not report is accepted",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid"},
			wantErr:   false,
		},
		{
			name:      "reported class matching the request is accepted",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "tool", Runtime: "kata-fc"},
			wantErr:   false,
		},
		{
			name:      "reported class differing from the request is a denial",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "dev", Runtime: "kata-fc"},
			wantErr:   true,
		},
		{
			name:      "runc is a denial",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "tool", Runtime: "runc"},
			wantErr:   true,
		},
		{
			name:      "an unknown runtime is a denial",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "tool", Runtime: "something-new"},
			wantErr:   true,
		},
		{
			name:      "kata-qemu is accepted",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "tool", Runtime: "kata-qemu"},
			wantErr:   false,
		},
		{
			name:      "gvisor is accepted",
			requested: "tool",
			resp:      LaunchResponse{SandboxID: "ns/sbx/uid", SandboxClass: "tool", Runtime: "gvisor"},
			wantErr:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyIsolation(tc.requested, tc.resp)
			if tc.wantErr && err == nil {
				t.Fatalf("VerifyIsolation(%q, %+v) = nil; want an error", tc.requested, tc.resp)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("VerifyIsolation(%q, %+v) = %v; want nil", tc.requested, tc.resp, err)
			}
		})
	}
}

// TestNew_RequiresSandboxClass pins the fail-closed construction: an executor
// that was never told which isolation posture to ask for cannot be built, so
// there is no code path that launches a tool under the cluster default.
func TestNew_RequiresSandboxClass(t *testing.T) {
	_, err := New(Config{Client: &mockClient{}, Tenant: "gibson-dev"})
	if err == nil {
		t.Fatal("New with no SandboxClass succeeded; want an error")
	}
}

// TestExecute_RequestsConfiguredSandboxClass pins that the class reaches the
// launch. Without it setec resolves the cluster default and gibson runs tool
// code under an isolation posture it never chose.
func TestExecute_RequestsConfiguredSandboxClass(t *testing.T) {
	var gotClass string
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			gotClass = req.SandboxClass
			return LaunchResponse{SandboxID: "sbx-1", SandboxClass: req.SandboxClass, Runtime: "kata-fc"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{markerLine("ok")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 0}, nil },
		kill: func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, c)
	var out wrapperspb.StringValue
	if err := e.ExecuteWithSpec(context.Background(), "hello", helloSpec, wrapperspb.String("in"), &out); err != nil {
		t.Fatalf("ExecuteWithSpec: %v", err)
	}
	if gotClass != "tool" {
		t.Fatalf("launch sandbox class = %q; want %q", gotClass, "tool")
	}
}

// TestExecute_MismatchedRuntime_Denied is the isolation gate: setec reports a
// runtime with no isolation boundary, so the tool must not run in it and the
// sandbox must be reaped.
func TestExecute_MismatchedRuntime_Denied(t *testing.T) {
	var killed atomic.Int32
	var streamed atomic.Int32
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			// Asked for the isolating class; got a shared-kernel runtime back.
			return LaunchResponse{SandboxID: "sbx-1", SandboxClass: req.SandboxClass, Runtime: "runc"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			streamed.Add(1)
			return &fixedLogs{}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 0}, nil },
		kill: func(context.Context, string) error { killed.Add(1); return nil },
	}
	e := newExecutor(t, c)
	var out wrapperspb.StringValue
	err := e.ExecuteWithSpec(context.Background(), "hello", helloSpec, wrapperspb.String("in"), &out)
	if err == nil {
		t.Fatal("ExecuteWithSpec succeeded on a non-isolating runtime; want a denial")
	}
	var ge *types.GibsonError
	if !errors.As(err, &ge) || ge.Code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("error = %v; want SANDBOX_POLICY_DENIED", err)
	}
	if !strings.Contains(err.Error(), "runc") {
		t.Fatalf("error %v does not name the offending runtime", err)
	}
	if killed.Load() != 1 {
		t.Fatalf("kill called %d times; want 1 — a refused sandbox must be reaped", killed.Load())
	}
	if streamed.Load() != 0 {
		t.Fatal("the executor read from a sandbox it refused")
	}
}

// TestExecute_MismatchedClass_Denied: setec bound the sandbox to a different
// class than the one requested.
func TestExecute_MismatchedClass_Denied(t *testing.T) {
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1", SandboxClass: "dev", Runtime: "kata-fc"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) { return &fixedLogs{}, nil },
		wait:      func(context.Context, string) (WaitResponse, error) { return WaitResponse{}, nil },
		kill:      func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, c)
	var out wrapperspb.StringValue
	err := e.ExecuteWithSpec(context.Background(), "hello", helloSpec, wrapperspb.String("in"), &out)
	if err == nil {
		t.Fatal("ExecuteWithSpec succeeded against the wrong sandbox class; want a denial")
	}
	var ge *types.GibsonError
	if !errors.As(err, &ge) || ge.Code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("error = %v; want SANDBOX_POLICY_DENIED", err)
	}
}
