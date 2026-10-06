// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import "github.com/zeroroot-ai/sdk/plugin/manifest"

// declaration is the plugin declaration in code (ADR-0097). The SDK validates
// it at start and reports it to the daemon over RegisterComponent. No manifest
// file exists, and the image carries none.
//
// The plugin runs as a pod (ADR-0065 R5). Each method declares only its name
// and description: the SDK derives the request and response contract from the
// Go types registered with plugin.WithHandler. The secrets broker is the only
// credential channel, and the health timers are the SDK defaults.
func declaration() *manifest.Manifest {
	return &manifest.Manifest{
		APIVersion: "plugin.gibson.zeroroot.ai/v1",
		Kind:       "Plugin",
		Metadata: manifest.ManifestMetadata{
			Name:        "gitlab",
			Version:     "0.1.0",
			Description: "GitLab plugin — curated read/write over the GitLab REST API (client-go).",
			Author:      "ZeroRoot",
		},
		Spec: manifest.ManifestSpec{
			WorkloadClass: "plugin",
			Runtime:       "pod",
			Methods: []manifest.MethodDecl{
				{Name: "GetProject", Description: "Fetch a project by numeric ID or namespace/path."},
				{Name: "ListIssues", Description: "List issues for a project, optionally filtered by state."},
				{Name: "CreateIssue", Description: "Open a new issue in a project (write)."},
			},
			Secrets: []manifest.SecretDecl{
				{Name: credName, Scope: "startup", Rotation: "live", Required: true},
			},
		},
	}
}
