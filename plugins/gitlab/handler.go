// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"

	gitlab "gitlab.com/gitlab-org/api/client-go"

	"github.com/zeroroot-ai/sdk/plugin"
)

// credName is the broker-qualified secret this plugin resolves. It is declared
// in plugin.yaml under spec.secrets; the SDK rejects any undeclared name before
// it reaches the broker.
const credName = "cred:gitlab_token"

// --- Typed method contracts (ADR-0065 R4) --------------------------------
//
// Each method declares a Go request/response struct pair. The SDK derives the
// method's JSON-Schema input/output contract from these types at registration
// (plugin.WithHandler). The fields are a curated, mission-shaped subset of the
// upstream client-go types — not the vendor's whole API.

// GetProjectRequest addresses one project by numeric ID or by
// "namespace/path" (either is accepted by the GitLab API).
type GetProjectRequest struct {
	Project string `json:"project"`
}

// Project is the curated view of a GitLab project this plugin returns.
type Project struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	DefaultBranch     string `json:"default_branch"`
	Visibility        string `json:"visibility"`
	WebURL            string `json:"web_url"`
}

// GetProjectResponse wraps the fetched project.
type GetProjectResponse struct {
	Project Project `json:"project"`
}

// Issue is the curated view of a GitLab issue. IID is the per-project issue
// number a human sees; ID is the instance-wide identifier.
type Issue struct {
	IID         int64  `json:"iid"`
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	State       string `json:"state"`
	Description string `json:"description"`
	WebURL      string `json:"web_url"`
}

// ListIssuesRequest lists issues for one project. State is one of "opened",
// "closed", or "all"; empty defaults to the GitLab API default.
type ListIssuesRequest struct {
	Project string `json:"project"`
	State   string `json:"state"`
}

// ListIssuesResponse carries the returned issues.
type ListIssuesResponse struct {
	Issues []Issue `json:"issues"`
}

// CreateIssueRequest opens a new issue. This is the write method that proves
// the R/W surface.
type CreateIssueRequest struct {
	Project     string   `json:"project"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
}

// CreateIssueResponse carries the newly created issue.
type CreateIssueResponse struct {
	Issue Issue `json:"issue"`
}

// --- Core logic ----------------------------------------------------------
//
// The core functions take an explicit *gitlab.Client so they are unit-testable
// against a cassette-backed client with no network and no token (see
// handler_test.go). Secret resolution and client construction live in the
// handler adapters below.

func getProject(_ context.Context, gl *gitlab.Client, req GetProjectRequest) (GetProjectResponse, error) {
	p, _, err := gl.Projects.GetProject(req.Project, &gitlab.GetProjectOptions{})
	if err != nil {
		return GetProjectResponse{}, fmt.Errorf("get project %s: %w", req.Project, err)
	}
	return GetProjectResponse{Project: toProject(p)}, nil
}

func listIssues(_ context.Context, gl *gitlab.Client, req ListIssuesRequest) (ListIssuesResponse, error) {
	opts := &gitlab.ListProjectIssuesOptions{}
	if req.State != "" {
		opts.State = gitlab.Ptr(req.State)
	}
	list, _, err := gl.Issues.ListProjectIssues(req.Project, opts)
	if err != nil {
		return ListIssuesResponse{}, fmt.Errorf("list issues for project %s: %w", req.Project, err)
	}
	out := make([]Issue, 0, len(list))
	for _, i := range list {
		out = append(out, toIssue(i))
	}
	return ListIssuesResponse{Issues: out}, nil
}

func createIssue(_ context.Context, gl *gitlab.Client, req CreateIssueRequest) (CreateIssueResponse, error) {
	opts := &gitlab.CreateIssueOptions{Title: gitlab.Ptr(req.Title)}
	if req.Description != "" {
		opts.Description = gitlab.Ptr(req.Description)
	}
	if len(req.Labels) > 0 {
		labels := gitlab.LabelOptions(req.Labels)
		opts.Labels = &labels
	}
	i, _, err := gl.Issues.CreateIssue(req.Project, opts)
	if err != nil {
		return CreateIssueResponse{}, fmt.Errorf("create issue in project %s: %w", req.Project, err)
	}
	return CreateIssueResponse{Issue: toIssue(i)}, nil
}

func toProject(p *gitlab.Project) Project {
	return Project{
		ID:                p.ID,
		PathWithNamespace: p.PathWithNamespace,
		Name:              p.Name,
		Description:       p.Description,
		DefaultBranch:     p.DefaultBranch,
		Visibility:        string(p.Visibility),
		WebURL:            p.WebURL,
	}
}

func toIssue(i *gitlab.Issue) Issue {
	return Issue{
		IID:         i.IID,
		ID:          i.ID,
		Title:       i.Title,
		State:       i.State,
		Description: i.Description,
		WebURL:      i.WebURL,
	}
}

// --- Handler adapters + Serve --------------------------------------------
//
// newClient resolves the GitLab token from the broker-backed secrets client
// the SDK injects into every handler context, then builds an authenticated
// client-go client. The token never appears in a log line or an error.
func newClient(ctx context.Context) (*gitlab.Client, error) {
	token, err := plugin.ResolveSecret(ctx, credName)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", credName, err)
	}
	gl, err := gitlab.NewClient(string(token))
	if err != nil {
		return nil, fmt.Errorf("build gitlab client: %w", err)
	}
	return gl, nil
}

func handleGetProject(ctx context.Context, req GetProjectRequest) (GetProjectResponse, error) {
	gl, err := newClient(ctx)
	if err != nil {
		return GetProjectResponse{}, err
	}
	return getProject(ctx, gl, req)
}

func handleListIssues(ctx context.Context, req ListIssuesRequest) (ListIssuesResponse, error) {
	gl, err := newClient(ctx)
	if err != nil {
		return ListIssuesResponse{}, err
	}
	return listIssues(ctx, gl, req)
}

func handleCreateIssue(ctx context.Context, req CreateIssueRequest) (CreateIssueResponse, error) {
	gl, err := newClient(ctx)
	if err != nil {
		return CreateIssueResponse{}, err
	}
	return createIssue(ctx, gl, req)
}

func main() {
	err := plugin.Serve(
		context.Background(),
		plugin.WithManifest(cmp.Or(os.Getenv("GIBSON_PLUGIN_MANIFEST"), "./plugin.yaml")),
		plugin.WithHandler("GetProject", handleGetProject),
		plugin.WithHandler("ListIssues", handleListIssues),
		plugin.WithHandler("CreateIssue", handleCreateIssue),
	)
	if err != nil {
		slog.Error("plugin exited with error", "err", err)
		os.Exit(1)
	}
}
