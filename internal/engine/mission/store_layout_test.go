package mission

import (
	"context"
	"errors"
	"testing"

	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

func sampleLayout(id string) *daemonpb.MissionLayout {
	return &daemonpb.MissionLayout{
		MissionDefinitionId: id,
		Nodes: []*daemonpb.NodePosition{
			{NodeId: "scan", X: 320.5, Y: 80},
			{NodeId: "enrich", X: 560, Y: 80},
		},
		Viewport: &daemonpb.MissionGraphViewport{X: -10, Y: 5, Zoom: 1.25},
	}
}

func TestSaveLayout_RoundTrip(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	version, err := store.SaveLayout(ctx, sampleLayout("def-1"), "")
	if err != nil {
		t.Fatalf("SaveLayout: %v", err)
	}
	if version != "1" {
		t.Errorf("first version = %q, want 1", version)
	}

	got, err := store.GetLayout(ctx, "def-1")
	if err != nil {
		t.Fatalf("GetLayout: %v", err)
	}
	if got == nil {
		t.Fatal("GetLayout returned nil after save")
	}
	if got.GetVersion() != "1" {
		t.Errorf("stored version = %q, want 1", got.GetVersion())
	}
	if len(got.GetNodes()) != 2 {
		t.Fatalf("stored nodes = %d, want 2", len(got.GetNodes()))
	}
	// Positions survive exactly, including the fractional coordinate.
	pos := map[string]*daemonpb.NodePosition{}
	for _, p := range got.GetNodes() {
		pos[p.GetNodeId()] = p
	}
	if pos["scan"].GetX() != 320.5 || pos["scan"].GetY() != 80 {
		t.Errorf("scan pos = (%v,%v), want (320.5,80)", pos["scan"].GetX(), pos["scan"].GetY())
	}
	if got.GetViewport().GetZoom() != 1.25 {
		t.Errorf("viewport zoom = %v, want 1.25", got.GetViewport().GetZoom())
	}
}

func TestGetLayout_AbsentReturnsNil(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	got, err := store.GetLayout(context.Background(), "never-saved")
	if err != nil {
		t.Fatalf("GetLayout: %v", err)
	}
	if got != nil {
		t.Errorf("want nil for absent layout, got %+v", got)
	}
}

func TestSaveLayout_StaleWriteRejected(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	v1, err := store.SaveLayout(ctx, sampleLayout("def-1"), "")
	if err != nil {
		t.Fatalf("first save: %v", err)
	}

	// A blind overwrite (empty expected_version over an existing layout) is a
	// stale write and must be rejected.
	if _, err := store.SaveLayout(ctx, sampleLayout("def-1"), ""); !errors.Is(err, ErrLayoutConflict) {
		t.Fatalf("blind overwrite: want ErrLayoutConflict, got %v", err)
	}

	// A save against a wrong version is rejected.
	if _, err := store.SaveLayout(ctx, sampleLayout("def-1"), "99"); !errors.Is(err, ErrLayoutConflict) {
		t.Fatalf("wrong version: want ErrLayoutConflict, got %v", err)
	}

	// A save against the current version succeeds and bumps the version.
	v2, err := store.SaveLayout(ctx, sampleLayout("def-1"), v1)
	if err != nil {
		t.Fatalf("correct-version save: %v", err)
	}
	if v2 != "2" {
		t.Errorf("second version = %q, want 2", v2)
	}
}

// Saving a layout must never touch the mission definition record (separate
// stores; the work-schema carries no presentation state).
func TestSaveLayout_DoesNotTouchDefinition(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	def := &missionv1.MissionDefinition{
		Id:    "def-xyz",
		Name:  "recon",
		Nodes: map[string]*missionv1.MissionNode{"scan": {Id: "scan", Type: missionv1.NodeType_NODE_TYPE_AGENT}},
	}
	if err := store.CreateDefinition(ctx, def); err != nil {
		t.Fatalf("CreateDefinition: %v", err)
	}
	before, _ := store.GetDefinition(ctx, "recon")

	if _, err := store.SaveLayout(ctx, sampleLayout("def-xyz"), ""); err != nil {
		t.Fatalf("SaveLayout: %v", err)
	}

	after, err := store.GetDefinition(ctx, "recon")
	if err != nil || after == nil {
		t.Fatalf("GetDefinition after save: %v", err)
	}
	// The definition is byte-identical (no presentation leaked in).
	beforeJSON, _ := MarshalDefinitionJSON(before)
	afterJSON, _ := MarshalDefinitionJSON(after)
	if string(beforeJSON) != string(afterJSON) {
		t.Errorf("mission definition changed after layout save:\nbefore=%s\nafter=%s", beforeJSON, afterJSON)
	}
}

func TestGetDefinitionByID(t *testing.T) {
	store, _ := newTestConnBoundStore(t)
	ctx := context.Background()

	def := &missionv1.MissionDefinition{Id: "id-123", Name: "scan-mission"}
	if err := store.CreateDefinition(ctx, def); err != nil {
		t.Fatalf("CreateDefinition: %v", err)
	}

	got, err := store.GetDefinitionByID(ctx, "id-123")
	if err != nil {
		t.Fatalf("GetDefinitionByID: %v", err)
	}
	if got == nil || got.GetName() != "scan-mission" {
		t.Fatalf("GetDefinitionByID = %+v, want name scan-mission", got)
	}

	missing, err := store.GetDefinitionByID(ctx, "nope")
	if err != nil {
		t.Fatalf("GetDefinitionByID(missing): %v", err)
	}
	if missing != nil {
		t.Errorf("want nil for unknown id, got %+v", missing)
	}
}
