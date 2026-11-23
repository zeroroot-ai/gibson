// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
)

// The sink writes the Application, the Repository and the Image of a scan into
// the World of the tenant of the call, with the edges that FindingPlaces reads,
// and no other tenant sees them (gibson#1469).
func TestIngestScanAnchors_LinkTheApplicationInTheTenantWorld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	ingestScanAnchors(reg, nil)(ctx, "acme", "mission-1", map[string]string{
		"application": "customer-portal", "repositoryUrl": "https://gitlab.com/examplebank/customer-portal",
		"commit": "abc", "ref": "main", "imageRef": "registry.example.com/portal@sha256:ab12",
	})
	ingestScanAnchors(nil, nil)(ctx, "acme", "m", nil)
	ingestScanAnchors(reg, nil)(ctx, "", "m", map[string]string{"application": "x", "repositoryUrl": "https://h.example/a/b"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(reg.For("acme").Entities()) == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	edges := map[string]brain.EntityEdge{}
	for _, e := range reg.For("acme").Entities() {
		if len(e.Edges) == 1 {
			edges[e.Label] = e.Edges[0]
		}
	}
	if got := edges["Application"]; got.Type != "HAS_REPOSITORY" || got.TargetKey != "gitlab.com/examplebank/customer-portal" {
		t.Errorf("Application edge = %+v", got)
	}
	if got := edges["Image"]; got.Type != "BUILT_FROM" || got.TargetKey != "gitlab.com/examplebank/customer-portal" {
		t.Errorf("Image edge = %+v", got)
	}
	if n := len(reg.For("other").Entities()); n != 0 {
		t.Errorf("another tenant holds %d entities", n)
	}
	if n := len(reg.For("acme").Entities()); n != 3 {
		t.Errorf("entities = %d, want 3 (a call with no tenant writes nothing)", n)
	}
}

// The sink warns, with a real logger, when a scan gets no anchor or when its
// image has no digest. The record names the mission and the tenant. A scan with
// full parameters logs nothing.
func TestIngestScanAnchors_WarnsWhenAScanGetsNoAnchor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	run := func(params map[string]string) string {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		ingestScanAnchors(reg, logger)(ctx, "acme", "mission-7", params)
		return buf.String()
	}
	full := map[string]string{
		"application": "portal", "repositoryUrl": "https://gitlab.com/g/p", "imageRef": "r.example/p@sha256:ab12",
	}
	if out := run(full); out != "" {
		t.Errorf("full parameters logged: %s", out)
	}
	noRepo := map[string]string{"application": "portal", "repositoryUrl": "not a url"}
	if out := run(noRepo); !strings.Contains(out, "gives no anchor") || !strings.Contains(out, "mission-7") || !strings.Contains(out, "acme") {
		t.Errorf("no anchor: log = %q", out)
	}
	tagOnly := map[string]string{"application": "portal", "repositoryUrl": "https://gitlab.com/g/p", "imageRef": "r.example/p:1.2"}
	if out := run(tagOnly); !strings.Contains(out, "no digest") {
		t.Errorf("tag-only image: log = %q", out)
	}
}
