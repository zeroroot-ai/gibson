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

	"github.com/google/go-github/v90/github"
)

// cassette is a committed HTTP fixture under testdata/. It records the single
// request a core function is expected to make against the GitHub REST API and
// the response the API returned. Replaying it through a cassette-backed
// *github.Client keeps every test fully hermetic — no daemon, no network, no
// token, no build tags (ADR-0065 R7). Record a new case by committing another
// cassette file and a sub-test that loads it.
//
// Response is the raw GitHub wire JSON (what go-github itself unmarshals), so
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
// the cassette recorded — and fails the test on any other. It never touches the
// network, so the go-github client it backs is entirely offline.
type cassetteRT struct {
	t testing.TB
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

// clientFor builds a go-github client whose transport is the cassette. The
// default BaseURL (api.github.com) is fine: the RoundTripper intercepts the
// request before it can leave the process.
func clientFor(t *testing.T, c cassette) *github.Client {
	t.Helper()
	gh, err := github.NewClient(github.WithTransport(cassetteRT{t: t, c: c}))
	if err != nil {
		t.Fatalf("build github client: %v", err)
	}
	return gh
}

func TestGetRepository(t *testing.T) {
	c := loadCassette(t, "testdata/get_repository.json")
	gh := clientFor(t, c)

	got, err := getRepository(context.Background(), gh, GetRepositoryRequest{Owner: "zeroroot-ai", Repo: "gibson"})
	if err != nil {
		t.Fatalf("getRepository: %v", err)
	}
	if got.Repository.FullName != "zeroroot-ai/gibson" {
		t.Errorf("FullName = %q, want zeroroot-ai/gibson", got.Repository.FullName)
	}
	if got.Repository.ID != 42 {
		t.Errorf("ID = %d, want 42", got.Repository.ID)
	}
	if got.Repository.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want main", got.Repository.DefaultBranch)
	}
	if got.Repository.Private {
		t.Errorf("Private = true, want false")
	}
}

func TestListIssues(t *testing.T) {
	c := loadCassette(t, "testdata/list_issues.json")
	gh := clientFor(t, c)

	got, err := listIssues(context.Background(), gh, ListIssuesRequest{Owner: "zeroroot-ai", Repo: "gibson", State: "open"})
	if err != nil {
		t.Fatalf("listIssues: %v", err)
	}
	if len(got.Issues) != 2 {
		t.Fatalf("got %d issues, want 2", len(got.Issues))
	}
	if got.Issues[0].Number != 1450 {
		t.Errorf("Issues[0].Number = %d, want 1450", got.Issues[0].Number)
	}
	if got.Issues[0].State != "open" {
		t.Errorf("Issues[0].State = %q, want open", got.Issues[0].State)
	}
}

func TestCreateIssue(t *testing.T) {
	c := loadCassette(t, "testdata/create_issue.json")
	gh := clientFor(t, c)

	got, err := createIssue(context.Background(), gh, CreateIssueRequest{
		Owner: "zeroroot-ai",
		Repo:  "gibson",
		Title: "Session affinity regression",
		Body:  "Two tool calls landed in different sandboxes.",
		Labels: []string{"bug"},
	})
	if err != nil {
		t.Fatalf("createIssue: %v", err)
	}
	if got.Issue.Number != 1601 {
		t.Errorf("Issue.Number = %d, want 1601", got.Issue.Number)
	}
	if got.Issue.Title != "Session affinity regression" {
		t.Errorf("Issue.Title = %q", got.Issue.Title)
	}
	if got.Issue.State != "open" {
		t.Errorf("Issue.State = %q, want open", got.Issue.State)
	}
}
