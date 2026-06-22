// Package mission — store_layout.go
//
// MissionLayout store: the per-tenant persistence for the MissionGraph
// flow-chart's saved diagram layout. It is deliberately SEPARATE from the
// mission definition store — the mission work-schema carries no presentation
// state. Keyed by mission_definition_id (the definition's stable GUID), not by
// name. Spec: MissionGraph epic (sdk#278, gibson#598).
package mission

import (
	"context"
	"fmt"
	"strconv"

	goredis "github.com/redis/go-redis/v9"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ErrLayoutConflict is returned by SaveLayout when expected_version does not
// match the currently-stored layout version (a stale write). Handlers map this
// to codes.Aborted.
var ErrLayoutConflict = fmt.Errorf("mission layout: version conflict (stale write)")

func cbMissionLayoutKey(missionDefID string) string {
	return fmt.Sprintf("gibson:mission-layout:%s", missionDefID)
}

// GetDefinitionByID resolves a mission definition by its stable id (GUID).
// Definitions are name-keyed in Redis, so this scans the definition index and
// matches on id. Returns nil, nil when no definition has that id.
func (s *ConnBoundMissionStore) GetDefinitionByID(ctx context.Context, id string) (*missionv1.MissionDefinition, error) {
	if id == "" {
		return nil, fmt.Errorf("mission definition id is required")
	}
	defs, err := s.ListDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	for _, def := range defs {
		if def.GetId() == id {
			return def, nil
		}
	}
	return nil, nil
}

// GetLayout returns the saved layout for a mission definition, or nil, nil when
// none has been saved.
func (s *ConnBoundMissionStore) GetLayout(ctx context.Context, missionDefID string) (*daemonpb.MissionLayout, error) {
	if missionDefID == "" {
		return nil, fmt.Errorf("mission definition id is required")
	}
	data, err := s.rdb.Get(ctx, cbMissionLayoutKey(missionDefID)).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get mission layout: %w", err)
	}
	var layout daemonpb.MissionLayout
	if err := protojson.Unmarshal([]byte(data), &layout); err != nil {
		return nil, fmt.Errorf("failed to unmarshal mission layout: %w", err)
	}
	return &layout, nil
}

// SaveLayout persists a hand-arranged layout, returning the new version token.
// It enforces optimistic concurrency: when a layout already exists, the caller's
// expectedVersion must match the stored version or ErrLayoutConflict is
// returned. An empty expectedVersion means "create if absent"; saving over an
// existing layout with an empty expectedVersion is treated as a conflict so a
// blind overwrite cannot silently clobber a concurrent edit.
//
// The compare-and-set runs inside a Redis WATCH transaction so concurrent saves
// cannot interleave.
func (s *ConnBoundMissionStore) SaveLayout(ctx context.Context, layout *daemonpb.MissionLayout, expectedVersion string) (string, error) {
	if layout == nil {
		return "", fmt.Errorf("mission layout cannot be nil")
	}
	id := layout.GetMissionDefinitionId()
	if id == "" {
		return "", fmt.Errorf("mission layout: mission_definition_id is required")
	}
	key := cbMissionLayoutKey(id)

	var newVersion string
	txf := func(tx *goredis.Tx) error {
		current := ""
		cur, err := tx.Get(ctx, key).Result()
		if err != nil && err != goredis.Nil {
			return err
		}
		if err == nil {
			var existing daemonpb.MissionLayout
			if uerr := protojson.Unmarshal([]byte(cur), &existing); uerr != nil {
				return fmt.Errorf("failed to unmarshal existing layout: %w", uerr)
			}
			current = existing.GetVersion()
		}
		// Concurrency gate. A stored layout requires a matching expected version;
		// an absent layout requires an empty expected version.
		if expectedVersion != current {
			return ErrLayoutConflict
		}
		newVersion = nextVersion(current)

		// Persist a copy with the new version stamped in.
		out := &daemonpb.MissionLayout{
			MissionDefinitionId: id,
			Nodes:               layout.GetNodes(),
			Viewport:            layout.GetViewport(),
			Version:             newVersion,
		}
		data, merr := protojson.Marshal(out)
		if merr != nil {
			return fmt.Errorf("failed to marshal mission layout: %w", merr)
		}
		_, perr := tx.TxPipelined(ctx, func(pipe goredis.Pipeliner) error {
			pipe.Set(ctx, key, string(data), 0)
			return nil
		})
		return perr
	}

	if err := s.rdb.Watch(ctx, txf, key); err != nil {
		if err == ErrLayoutConflict {
			return "", err
		}
		if err == goredis.TxFailedErr {
			// Key changed between WATCH and EXEC — a concurrent save won the race.
			return "", ErrLayoutConflict
		}
		return "", fmt.Errorf("failed to save mission layout: %w", err)
	}
	return newVersion, nil
}

// nextVersion produces the successor revision token. Versions are simple
// monotonically-increasing integers rendered as strings; "" (no prior layout)
// becomes "1".
func nextVersion(current string) string {
	if current == "" {
		return "1"
	}
	n, err := strconv.Atoi(current)
	if err != nil {
		// Non-numeric legacy token: restart the sequence deterministically.
		return "1"
	}
	return strconv.Itoa(n + 1)
}
