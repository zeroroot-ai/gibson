// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — catalog_missions_test.go unit tests for
// DaemonService.ListCatalogMissions and DaemonService.RenderCatalogMission.
//
// Spec: gibson#631 (a person cannot submit a catalog mission).
package api

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/cueruntime"
	"github.com/zeroroot-ai/gibson/internal/platform/missioncatalog"
)

func catalogServer() *DaemonServer {
	return &DaemonServer{logger: slog.New(slog.DiscardHandler)}
}

// The listing is the whole catalog, and it names what each mission needs. A
// listing that returned nothing would read as "the platform ships no missions".
func TestListCatalogMissions_ListsEveryCheckedInMissionWithItsParameters(t *testing.T) {
	t.Parallel()

	resp, err := catalogServer().ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}

	want := missioncatalog.Names()
	if len(want) == 0 {
		t.Fatal("the embedded catalog is empty; this test would pass on anything")
	}
	got := make([]string, 0, len(resp.GetMissions()))
	for _, m := range resp.GetMissions() {
		got = append(got, m.GetName())
	}
	if !slices.Equal(got, want) {
		t.Fatalf("listed %v, want %v in that order", got, want)
	}

	for _, m := range resp.GetMissions() {
		// The description and version come from the rendered definition, not
		// from a second table that would drift from the mission it describes.
		if m.GetDescription() == "" {
			t.Errorf("%s: no description", m.GetName())
		}
		if m.GetVersion() == "" {
			t.Errorf("%s: no version", m.GetName())
		}
		// declared_params must BE the closed set, because a caller builds its
		// render request from it. A short list sends a render that fails on a
		// missing key; a long one fails on an unknown key.
		src, serr := missioncatalog.Source(m.GetName())
		if serr != nil {
			t.Fatalf("Source(%s): %v", m.GetName(), serr)
		}
		declared, derr := cueruntime.DeclaredParams(src)
		if derr != nil {
			t.Fatalf("DeclaredParams(%s): %v", m.GetName(), derr)
		}
		slices.Sort(declared)
		if !slices.Equal(m.GetDeclaredParams(), declared) {
			t.Errorf("%s: declared_params = %v, want %v", m.GetName(), m.GetDeclaredParams(), declared)
		}
	}
}

// The listing must not leak the values it renders with. It renders each mission
// to read its description, and those placeholder values are not a caller's.
func TestListCatalogMissions_ReturnsNamesNotValues(t *testing.T) {
	t.Parallel()

	resp, err := catalogServer().ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}
	for _, m := range resp.GetMissions() {
		for _, p := range m.GetDeclaredParams() {
			if p == "placeholder" {
				t.Errorf("%s: a rendered placeholder value reached declared_params", m.GetName())
			}
		}
	}
}

// A caller that builds its request from the listing can render.
func TestRenderCatalogMission_RendersWhatTheListingDeclared(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	listed, err := srv.ListCatalogMissions(context.Background(), &daemonpb.ListCatalogMissionsRequest{})
	if err != nil {
		t.Fatalf("ListCatalogMissions: %v", err)
	}

	for _, m := range listed.GetMissions() {
		params := make(map[string]string, len(m.GetDeclaredParams()))
		for _, name := range m.GetDeclaredParams() {
			params[name] = "v-" + name
		}

		resp, rerr := srv.RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: m.GetName(), Params: params})
		if rerr != nil {
			t.Fatalf("RenderCatalogMission(%s): %v", m.GetName(), rerr)
		}
		if resp.GetMission().GetName() != m.GetName() {
			t.Errorf("%s: rendered mission is named %q", m.GetName(), resp.GetMission().GetName())
		}
		if len(resp.GetMission().GetNodes()) == 0 {
			t.Errorf("%s: rendered definition has no nodes", m.GetName())
		}
		// The source is returned verbatim so a person reads what the daemon
		// will run rather than trusting a rendered summary.
		if !strings.Contains(resp.GetSource(), "mission:") {
			t.Errorf("%s: the returned source does not look like the mission's CUE", m.GetName())
		}
	}
}

// The smuggling defence, on this path too. No mission declares a target or a
// host, so a dropped key would leave a caller believing it had redirected the
// scan. Asserted here rather than inferred from the shared resolver.
func TestRenderCatalogMission_UnknownParameterIsRefusedNotDropped(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)

	params := map[string]string{"host": "evil.example.com"}
	for _, d := range declared {
		params[d] = "v-" + d
	}

	_, err := srv.RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: params})
	if err == nil {
		t.Fatal("an unknown parameter must be refused; dropping it would let a caller believe host: bound")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("the refusal does not name the unknown key: %v", err)
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// The property the closed set exists for, said as its own test: a parameter
// cannot supply the target.
//
// The runtime target binds from the mission's target at submit and from nowhere
// else, so a caller that could smuggle one through a parameter could point a
// run at a cluster the tenant never registered. No mission declares `target`,
// `host`, `url` or `targetRef`, and each is refused by name rather than
// dropped.
func TestRenderCatalogMission_AParameterCannotSupplyTheTarget(t *testing.T) {
	t.Parallel()

	srv := catalogServer()
	for _, mission := range missioncatalog.Names() {
		src, serr := missioncatalog.Source(mission)
		if serr != nil {
			t.Fatalf("Source(%s): %v", mission, serr)
		}
		declared, derr := cueruntime.DeclaredParams(src)
		if derr != nil {
			t.Fatalf("DeclaredParams(%s): %v", mission, derr)
		}

		for _, smuggled := range []string{"target", "targetRef", "host", "url"} {
			// A mission that DID declare one of these would make the check
			// vacuous, so say so rather than passing quietly.
			if slices.Contains(declared, smuggled) {
				t.Fatalf("mission %q declares a parameter named %q; the runtime target must not be caller-supplied",
					mission, smuggled)
			}

			params := map[string]string{smuggled: "evil.example.com"}
			for _, d := range declared {
				params[d] = "v-" + d
			}
			_, err := srv.RenderCatalogMission(context.Background(),
				&daemonpb.RenderCatalogMissionRequest{Name: mission, Params: params})
			if err == nil {
				t.Errorf("mission %q accepted a %q parameter", mission, smuggled)
				continue
			}
			if !strings.Contains(err.Error(), smuggled) {
				t.Errorf("mission %q: the refusal does not name %q: %v", mission, smuggled, err)
			}
		}
	}
}

// Every missing parameter at once. A caller wiring this up should not discover
// them one render at a time.
func TestRenderCatalogMission_MissingParametersReportedTogether(t *testing.T) {
	t.Parallel()

	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)
	if len(declared) < 2 {
		t.Skipf("%s declares %d parameters; this asserts two missing at once", name, len(declared))
	}
	slices.Sort(declared)

	_, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: map[string]string{}})
	if err == nil {
		t.Fatal("a render with no parameters must fail for a mission that takes some")
	}
	for _, want := range declared[:2] {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the missing parameter %q: %v", want, err)
		}
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// An unknown name is the caller's mistake, and the error names what the catalog
// does ship — which is what a person needs after a typo.
func TestRenderCatalogMission_UnknownNameNamesWhatExists(t *testing.T) {
	t.Parallel()

	_, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: "no-such-mission"})
	if err == nil {
		t.Fatal("an unknown mission name must be refused")
	}
	for _, want := range missioncatalog.Names() {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the checked-in mission %q: %v", want, err)
		}
	}
	assertGRPCStatusCode(t, err, "InvalidArgument")
}

// A name is required, and the refusal lists the catalog rather than just
// saying "name is required".
func TestRenderCatalogMission_EmptyNameIsRefused(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"", "   "} {
		_, err := catalogServer().RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: name})
		if err == nil {
			t.Fatalf("name %q was accepted", name)
		}
		assertGRPCStatusCode(t, err, "InvalidArgument")
	}
}

// A path instead of a name is refused, so a caller cannot read a file outside
// the embedded catalog.
func TestRenderCatalogMission_APathIsNotAName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"../scan", "missions/scan", "scan.cue"} {
		_, err := catalogServer().RenderCatalogMission(context.Background(),
			&daemonpb.RenderCatalogMissionRequest{Name: name})
		if err == nil {
			t.Errorf("name %q was accepted as a mission name", name)
		}
	}
}

// The person path and the agent path must render the SAME definition for the
// same inputs. Two resolutions of one catalog is the duplicate ADR-0027
// forbids, and this is what keeps them one.
func TestRenderCatalogMission_AgreesWithTheAgentPath(t *testing.T) {
	t.Parallel()

	name := missioncatalog.Names()[0]
	src, _ := missioncatalog.Source(name)
	declared, _ := cueruntime.DeclaredParams(src)
	params := make(map[string]string, len(declared))
	for _, d := range declared {
		params[d] = "v-" + d
	}

	resp, err := catalogServer().RenderCatalogMission(context.Background(),
		&daemonpb.RenderCatalogMissionRequest{Name: name, Params: params})
	if err != nil {
		t.Fatalf("RenderCatalogMission: %v", err)
	}

	// missioncatalog.Render is what the harness callback calls. Same function,
	// so this asserts this handler adds no second rendering step of its own.
	want, err := missioncatalog.Render(context.Background(), name, params)
	if err != nil {
		t.Fatalf("missioncatalog.Render: %v", err)
	}
	if got, exp := len(resp.GetMission().GetNodes()), len(want.GetNodes()); got != exp {
		t.Errorf("the person path rendered %d nodes, the agent path %d", got, exp)
	}
	if resp.GetMission().GetName() != want.GetName() {
		t.Errorf("names differ: %q vs %q", resp.GetMission().GetName(), want.GetName())
	}
}
