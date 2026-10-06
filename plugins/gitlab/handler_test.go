// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

// cassette is a committed HTTP fixture under testdata/. It records the single
// request a core function is expected to make against the GitLab REST API and
// the response the API returned. Replaying it through a cassette-backed
// *gitlab.Client keeps every test fully hermetic — no daemon, no network, no
// token, no build tags (ADR-0065 R7). Record a new case by committing another
// cassette file and a sub-test that loads it.
//
// Response is the raw GitLab wire JSON (what client-go itself unmarshals), so
// the fixtures double as a check that the curated mapping in handler.go tracks
// the upstream field names.
type cassette struct {
	Method   string          `json:"method"`
	Path     string          `json:"path"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
}

func loadCassette(t *testing.T, path string) cassette {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cassette %s: %v", path, err)
	}
	var c cassette
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode cassette %s: %v", path, err)
	}
	return c
}

// cassetteRT is an http.RoundTripper that answers exactly one request — the one
// the cassette recorded — and fails on any other. It never touches the network,
// so the client-go client it backs is entirely offline.
type cassetteRT struct {
	c cassette
}

func (rt cassetteRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != rt.c.Method || req.URL.Path != rt.c.Path {
		return nil, fmt.Errorf("unexpected request %s %s (cassette wants %s %s)",
			req.Method, req.URL.Path, rt.c.Method, rt.c.Path)
	}
	return &http.Response{
		StatusCode: rt.c.Status,
		Body:       io.NopCloser(bytes.NewReader(rt.c.Response)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

// clientFor builds a client-go client whose HTTP transport is the cassette. The
// default base URL (gitlab.com/api/v4) is fine: the RoundTripper intercepts the
// request before it can leave the process. The token is a throwaway.
func clientFor(t *testing.T, c cassette) *gitlab.Client {
	t.Helper()
	gl, err := gitlab.NewClient("test-token",
		gitlab.WithHTTPClient(&http.Client{Transport: cassetteRT{c: c}}))
	if err != nil {
		t.Fatalf("build gitlab client: %v", err)
	}
	return gl
}

func TestGetProject(t *testing.T) {
	c := loadCassette(t, "testdata/get_project.json")
	gl := clientFor(t, c)

	got, err := getProject(context.Background(), gl, GetProjectRequest{Project: "9001"})
	if err != nil {
		t.Fatalf("getProject: %v", err)
	}
	if got.Project.PathWithNamespace != "zeroroot-ai/gibson" {
		t.Errorf("PathWithNamespace = %q, want zeroroot-ai/gibson", got.Project.PathWithNamespace)
	}
	if got.Project.ID != 9001 {
		t.Errorf("ID = %d, want 9001", got.Project.ID)
	}
	if got.Project.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main", got.Project.DefaultBranch)
	}
	if got.Project.Visibility != "private" {
		t.Errorf("Visibility = %q, want private", got.Project.Visibility)
	}
}

func TestListIssues(t *testing.T) {
	c := loadCassette(t, "testdata/list_issues.json")
	gl := clientFor(t, c)

	got, err := listIssues(context.Background(), gl, ListIssuesRequest{Project: "9001", State: "opened"})
	if err != nil {
		t.Fatalf("listIssues: %v", err)
	}
	if len(got.Issues) != 2 {
		t.Fatalf("got %d issues, want 2", len(got.Issues))
	}
	if got.Issues[0].IID != 12 {
		t.Errorf("Issues[0].IID = %d, want 12", got.Issues[0].IID)
	}
	if got.Issues[0].State != "opened" {
		t.Errorf("Issues[0].State = %q, want opened", got.Issues[0].State)
	}
}

func TestCreateIssue(t *testing.T) {
	c := loadCassette(t, "testdata/create_issue.json")
	gl := clientFor(t, c)

	got, err := createIssue(context.Background(), gl, CreateIssueRequest{
		Project:     "9001",
		Title:       "Runner cannot reach the daemon",
		Description: "The connector-operator proxy is refusing streamable-http.",
		Labels:      []string{"bug"},
	})
	if err != nil {
		t.Fatalf("createIssue: %v", err)
	}
	if got.Issue.IID != 34 {
		t.Errorf("Issue.IID = %d, want 34", got.Issue.IID)
	}
	if got.Issue.Title != "Runner cannot reach the daemon" {
		t.Errorf("Issue.Title = %q", got.Issue.Title)
	}
	if got.Issue.State != "opened" {
		t.Errorf("Issue.State = %q, want opened", got.Issue.State)
	}
}
