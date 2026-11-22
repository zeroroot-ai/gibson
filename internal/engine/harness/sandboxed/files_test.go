// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The files of a spec reach the launch request, so the sandbox places them
// before the tool starts.
func TestExecute_PassesTheFilesToTheLaunch(t *testing.T) {
	var got LaunchRequest
	c := &mockClient{launch: func(_ context.Context, r LaunchRequest) (LaunchResponse, error) {
		got = r
		return LaunchResponse{}, status.Error(codes.Internal, "stop after the launch")
	}}
	e := newExecutor(t, c)
	spec := helloSpec
	spec.Files = []File{
		{Path: "skill/scripts/run.sh", Content: []byte("#!/bin/sh\n"), Mode: 0o555},
		{Path: "skill/references/a.md", Content: []byte("guide"), Mode: 0o444},
	}
	_ = e.ExecuteWithSpec(context.Background(), "skill-script", spec, wrapperspb.String("x"), &wrapperspb.StringValue{})
	if len(got.Files) != 2 || got.Files[0].Path != "skill/scripts/run.sh" || got.Files[0].Mode != 0o555 ||
		string(got.Files[1].Content) != "guide" {
		t.Fatalf("launch files = %+v", got.Files)
	}
}

// A launch that setec refuses as invalid, with files, tells the author why,
// with the text of setec. A refusal without files keeps the plain message.
func TestExecute_SurfacesTheSizeCheckOfTheFiles(t *testing.T) {
	const setecText = "files: the Secret of the files would hold 600000 bytes, above 524288"
	c := &mockClient{launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
		return LaunchResponse{}, status.Error(codes.InvalidArgument, setecText)
	}}
	e := newExecutor(t, c)
	spec := helloSpec
	spec.Files = []File{{Path: "skill/big", Content: []byte("x"), Mode: 0o444}}
	err := e.ExecuteWithSpec(context.Background(), "skill-script", spec, wrapperspb.String("x"), &wrapperspb.StringValue{})
	if err == nil || !strings.Contains(err.Error(), setecText) || !strings.Contains(err.Error(), "files of the Agent Skill") {
		t.Fatalf("err = %v, want the text of setec and the words that name the files", err)
	}

	err = e.ExecuteWithSpec(context.Background(), "nmap", helloSpec, wrapperspb.String("x"), &wrapperspb.StringValue{})
	if err == nil || strings.Contains(err.Error(), "files of the Agent Skill") {
		t.Fatalf("a launch with no files must keep the plain message, got %v", err)
	}
}
