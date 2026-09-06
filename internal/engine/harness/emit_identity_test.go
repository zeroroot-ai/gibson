// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// An agent names a brand-new entity by the coordinate it observed, and it never
// names an entity by a raw brain id (ADR-0012, "Entity references are
// generational handles; new entities are named by coordinate"; gibson#1259).
// Brain ids are replay-deterministic and enumerable, so accepting one from the
// payload would let a compromised tool choose the identity its emit lands
// under, and so attach fabricated evidence to a name some other mission's
// evidence already owns.
//
// The two emit messages need two different guards, because they are in two
// different states:
//
//   - ObserveRequest carries no identifier at all. There is nothing to reject,
//     so the guard is a structural one over the generated descriptor: it fails
//     if an observation ever grows a field that names an entity by id.
//
//   - SubmitFindingRequest carries a legacy `id` field that predates the
//     decision and lives in the OSS SDK, so it cannot simply be deleted from
//     here. The guard is therefore behavioural: the daemon must ignore it.
//
// The generational-handle half of that ADR section — reference by the opaque
// handle a WorldView slice carried — now HAS a gibson surface: the WorldView
// read (worldview.go, gibson#1377) projects a mission-Scope-limited slice in
// which every entity is named by a server-minted, non-constructible handle. So
// a brain entity IS shown to an agent, but only ever behind a handle it cannot
// forge or iterate — never a raw brain id. This test's guard is unchanged and
// still correct: it forbids a brain-entity id in an EMIT envelope (the write
// path), and `handle` is in brainEntityNouns precisely so no emit field may
// smuggle one back in. Reading a slice (WorldView) and writing an emit
// (Observe/SubmitFinding) are different directions; the read introduced no emit
// field, so nothing here changed. See ADR-0012's WorldView section.

// brainEntityNouns are the things the tenant World is made of. A field only
// trips the guard when it names an id OF one of these: the emit envelope
// legitimately carries mission, task, run and target ids (provenance and
// server-side scope resolution, gibson#1256), and a host's `cloud_id` is a
// coordinate — a strong identity signal the agent genuinely observed — not a
// reference into the World.
var brainEntityNouns = []string{
	"node", "entity", "brain", "graph", "world", "handle",
	"host", "finding", "observation", "domain", "subdomain",
	"credential", "account", "port", "surprise", "label",
}

// namesABrainEntityID reports whether a proto field name reads as a reference
// to an entity the brain already holds — the shape of field ADR-0012 says an
// emit must not carry.
func namesABrainEntityID(field string) bool {
	if field == "id" {
		return true
	}
	prefix, ok := strings.CutSuffix(field, "_id")
	if !ok {
		return false
	}
	for _, noun := range brainEntityNouns {
		if prefix == noun || strings.HasSuffix(prefix, "_"+noun) {
			return true
		}
	}
	return false
}

// TestNamesABrainEntityIDFires is the guard on the guard. A predicate that
// silently matched nothing would make the descriptor walk below pass for the
// wrong reason, so it is pinned against both the names it must catch and the
// names it must not.
func TestNamesABrainEntityIDFires(t *testing.T) {
	mustCatch := []string{
		"id",
		"brain_id", "node_id", "entity_id", "graph_id", "world_id", "handle_id",
		"host_id", "finding_id", "domain_id", "subdomain_id",
		"credential_id", "account_id", "port_id", "label_id",
		"parent_host_id", "related_finding_id",
	}
	for _, name := range mustCatch {
		if !namesABrainEntityID(name) {
			t.Errorf("%s references a brain entity but the guard does not catch it", name)
		}
	}

	mustNotCatch := []string{
		// Coordinates and strong identity signals — what an agent actually
		// observed, and the whole "create by coordinate" half of the decision.
		"address", "ssh_host_key", "cloud_id", "fqdn", "name", "identifier",
		"secret_hash", "fingerprint", "number", "protocol", "path",
		// Envelope: provenance and the ids the daemon resolves scope from.
		"mission_id", "task_id", "trace_id", "span_id", "mission_run_id",
		"agent_run_id", "tool_execution_id", "target_id", "work_id",
	}
	for _, name := range mustNotCatch {
		if namesABrainEntityID(name) {
			t.Errorf("%s is not a brain entity reference but the guard catches it", name)
		}
	}
}

// TestObservationsNameEntitiesByCoordinate walks the real generated descriptors
// of every observation an agent can emit and asserts none of them can carry a
// reference to an entity the brain already holds. Read off the descriptor
// rather than a hand-maintained list, so a newly added observation — or a new
// field on an existing one — is covered the moment it is generated.
//
// Only the `observation` oneof is walked. The `context` envelope is a different
// surface with a different rule: it carries mission/task/run ids on purpose,
// and what the daemon may believe from it is gibson#1256's question.
func TestObservationsNameEntitiesByCoordinate(t *testing.T) {
	desc := (&harnesspb.ObserveRequest{}).ProtoReflect().Descriptor()
	observation := desc.Oneofs().ByName("observation")
	if observation == nil {
		t.Fatal("ObserveRequest has no `observation` oneof; the guard is walking nothing")
	}
	if observation.Fields().Len() == 0 {
		t.Fatal("the `observation` oneof is empty; the guard is walking nothing")
	}

	walked := 0
	seen := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor, path string)
	walk = func(md protoreflect.MessageDescriptor, path string) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true
		walked++
		for i := range md.Fields().Len() {
			f := md.Fields().Get(i)
			if namesABrainEntityID(string(f.Name())) {
				t.Errorf("%s.%s references a brain entity by id; an agent names a new "+
					"entity by the coordinate it observed, never by a brain id (ADR-0012)",
					path, f.Name())
			}
			if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
				walk(f.Message(), path+"."+string(f.Name()))
			}
		}
	}
	for i := range observation.Fields().Len() {
		f := observation.Fields().Get(i)
		walk(f.Message(), string(f.Name()))
	}

	// Strictly more messages than observation types: the host observation
	// nests port detail, which nests endpoint, technology and certificate
	// detail. A walk that stopped at the top level would visit exactly as
	// many messages as there are observation types and would miss every
	// nested field, so equality is a failure, not a pass.
	if walked <= observation.Fields().Len() {
		t.Fatalf("walked %d messages for %d observation types; the walk did not descend "+
			"into nested observation detail", walked, observation.Fields().Len())
	}
}

// TestSubmittedFindingIdentityIsServerAssigned covers the field the descriptor
// walk cannot reach. typespb.Finding carries an `id` the emitter fills in; the
// daemon must assign the finding's identity itself and drop what arrived.
func TestSubmittedFindingIdentityIsServerAssigned(t *testing.T) {
	t.Run("the id the payload names is not adopted", func(t *testing.T) {
		claimed := uuid.NewString()

		got := protoFindingToFinding(&typespb.Finding{
			Id:       claimed,
			Title:    "reflected xss",
			Severity: typespb.FindingSeverity_FINDING_SEVERITY_HIGH,
		})

		if got.ID.String() == claimed {
			t.Fatalf("the finding kept the identity its payload claimed (%s); a remote "+
				"emitter that can choose a brain id can attach fabricated evidence to a "+
				"name another mission's finding owns (ADR-0012)", claimed)
		}
	})

	t.Run("an identity is assigned all the same", func(t *testing.T) {
		got := protoFindingToFinding(&typespb.Finding{Title: "open redirect"})

		if got.ID.String() == "" {
			t.Fatal("no identity was assigned; refusing the payload's id must not leave the finding nameless")
		}
		if _, err := uuid.Parse(got.ID.String()); err != nil {
			t.Fatalf("assigned identity %q is not a well-formed id: %v", got.ID.String(), err)
		}
	})

	t.Run("two emits claiming one id get two identities", func(t *testing.T) {
		claimed := uuid.NewString()

		first := protoFindingToFinding(&typespb.Finding{Id: claimed, Title: "first"})
		second := protoFindingToFinding(&typespb.Finding{Id: claimed, Title: "second"})

		if first.ID.String() == second.ID.String() {
			t.Fatalf("both emits landed on identity %s; a payload id must not be able to "+
				"collide two findings onto one name", first.ID.String())
		}
	})

	t.Run("what the agent does author survives", func(t *testing.T) {
		got := protoFindingToFinding(&typespb.Finding{
			Id:          uuid.NewString(),
			Title:       "sql injection",
			Description: "boolean-based blind, /search?q=",
			Severity:    typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL,
			Category:    "injection",
			Confidence:  0.9,
		})

		if got.Title != "sql injection" {
			t.Errorf("title = %q, want %q", got.Title, "sql injection")
		}
		if got.Description != "boolean-based blind, /search?q=" {
			t.Errorf("description = %q, want the emitted one", got.Description)
		}
		if got.Severity != agent.SeverityCritical {
			t.Errorf("severity = %q, want critical", got.Severity)
		}
		if got.Category != "injection" {
			t.Errorf("category = %q, want %q", got.Category, "injection")
		}
		if got.Confidence != 0.9 {
			t.Errorf("confidence = %v, want 0.9", got.Confidence)
		}
	})
}
