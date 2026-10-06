// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/go-github/v90/github"
	"github.com/zeroroot-ai/sdk/plugin"
)

// credName is the broker-qualified secret this plugin resolves for every call.
// It is declared in plugin.yaml under spec.secrets; the SDK rejects any name
// that is not declared there before it ever reaches the broker.
const credName = "cred:github_token"

// --- Typed method contracts (ADR-0065 R4) --------------------------------
//
// Each method declares a Go request/response struct pair. The SDK derives the
// method's JSON-Schema input/output contract from these types at registration
// (plugin.WithHandler). There is no .proto and no generated code — the Go type
// IS the contract. Fields are deliberately a curated subset of the upstream
// go-github types: a plugin exposes a stable, mission-shaped surface, not the
// vendor's entire API.

// GetRepositoryRequest addresses one repository by owner and name.
type GetRepositoryRequest struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

// Repository is the curated view of a GitHub repository this plugin returns.
type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Description   string `json:"description"`
	Private       bool   `json:"private"`
	Fork          bool   `json:"fork"`
	DefaultBranch string `json:"default_branch"`
	Language      string `json:"language"`
	Stargazers    int    `json:"stargazers"`
	HTMLURL       string `json:"html_url"`
}

// GetRepositoryResponse wraps the fetched repository.
type GetRepositoryResponse struct {
	Repository Repository `json:"repository"`
}

// Issue is the curated view of a GitHub issue.
type Issue struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

// ListIssuesRequest lists issues for one repository. State is one of
// "open", "closed", or "all"; empty defaults to GitHub's "open".
type ListIssuesRequest struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
	State string `json:"state"`
}

// ListIssuesResponse carries the returned issues.
type ListIssuesResponse struct {
	Issues []Issue `json:"issues"`
}

// CreateIssueRequest opens a new issue. This is the write method that proves
// the R/W surface.
type CreateIssueRequest struct {
	Owner  string   `json:"owner"`
	Repo   string   `json:"repo"`
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

// CreateIssueResponse carries the newly created issue.
type CreateIssueResponse struct {
	Issue Issue `json:"issue"`
}

// --- Core logic ----------------------------------------------------------
//
// The core functions take an explicit *github.Client so they are unit-testable
// against a cassette-backed client with no network and no token (see
// handler_test.go). Secret resolution and client construction live in the
// handler adapters below, exactly as the daemon drives them at runtime.

func getRepository(ctx context.Context, gh *github.Client, req GetRepositoryRequest) (GetRepositoryResponse, error) {
	r, _, err := gh.Repositories.Get(ctx, req.Owner, req.Repo)
	if err != nil {
		return GetRepositoryResponse{}, fmt.Errorf("get repository %s/%s: %w", req.Owner, req.Repo, err)
	}
	return GetRepositoryResponse{Repository: toRepository(r)}, nil
}

func listIssues(ctx context.Context, gh *github.Client, req ListIssuesRequest) (ListIssuesResponse, error) {
	opts := &github.IssueListByRepoOptions{}
	if req.State != "" {
		opts.State = req.State
	}
	list, _, err := gh.Issues.ListByRepo(ctx, req.Owner, req.Repo, opts)
	if err != nil {
		return ListIssuesResponse{}, fmt.Errorf("list issues %s/%s: %w", req.Owner, req.Repo, err)
	}
	out := make([]Issue, 0, len(list))
	for _, i := range list {
		out = append(out, toIssue(i))
	}
	return ListIssuesResponse{Issues: out}, nil
}

func createIssue(ctx context.Context, gh *github.Client, req CreateIssueRequest) (CreateIssueResponse, error) {
	body := github.CreateIssueRequest{Title: req.Title}
	if req.Body != "" {
		body.Body = github.Ptr(req.Body)
	}
	if len(req.Labels) > 0 {
		body.Labels = req.Labels
	}
	i, _, err := gh.Issues.Create(ctx, req.Owner, req.Repo, body)
	if err != nil {
		return CreateIssueResponse{}, fmt.Errorf("create issue in %s/%s: %w", req.Owner, req.Repo, err)
	}
	return CreateIssueResponse{Issue: toIssue(i)}, nil
}

// toRepository maps the upstream go-github type to the curated view, using the
// generated Get* accessors so a missing (nil) field decodes to its zero value
// rather than panicking.
func toRepository(r *github.Repository) Repository {
	return Repository{
		ID:            r.GetID(),
		FullName:      r.GetFullName(),
		Description:   r.GetDescription(),
		Private:       r.GetPrivate(),
		Fork:          r.GetFork(),
		DefaultBranch: r.GetDefaultBranch(),
		Language:      r.GetLanguage(),
		Stargazers:    r.GetStargazersCount(),
		HTMLURL:       r.GetHTMLURL(),
	}
}

func toIssue(i *github.Issue) Issue {
	return Issue{
		Number:  i.GetNumber(),
		Title:   i.GetTitle(),
		State:   i.GetState(),
		Body:    i.GetBody(),
		HTMLURL: i.GetHTMLURL(),
	}
}

// --- Handler adapters + Serve --------------------------------------------
//
// newClient resolves the GitHub token from the broker-backed secrets client
// the SDK injects into every handler context, then builds an authenticated
// go-github client. The token never appears in a log line or an error.
func newClient(ctx context.Context) (*github.Client, error) {
	token, err := plugin.ResolveSecret(ctx, credName)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", credName, err)
	}
	gh, err := github.NewClient(github.WithAuthToken(string(token)))
	if err != nil {
		return nil, fmt.Errorf("build github client: %w", err)
	}
	return gh, nil
}

func handleGetRepository(ctx context.Context, req GetRepositoryRequest) (GetRepositoryResponse, error) {
	gh, err := newClient(ctx)
	if err != nil {
		return GetRepositoryResponse{}, err
	}
	return getRepository(ctx, gh, req)
}

func handleListIssues(ctx context.Context, req ListIssuesRequest) (ListIssuesResponse, error) {
	gh, err := newClient(ctx)
	if err != nil {
		return ListIssuesResponse{}, err
	}
	return listIssues(ctx, gh, req)
}

func handleCreateIssue(ctx context.Context, req CreateIssueRequest) (CreateIssueResponse, error) {
	gh, err := newClient(ctx)
	if err != nil {
		return CreateIssueResponse{}, err
	}
	return createIssue(ctx, gh, req)
}

func main() {
	err := plugin.Serve(
		context.Background(),
		plugin.WithManifest(cmp.Or(os.Getenv("GIBSON_PLUGIN_MANIFEST"), "./plugin.yaml")),
		plugin.WithHandler("GetRepository", handleGetRepository),
		plugin.WithHandler("ListIssues", handleListIssues),
		plugin.WithHandler("CreateIssue", handleCreateIssue),
	)
	if err != nil {
		slog.Error("plugin exited with error", "err", err)
		os.Exit(1)
	}
}
