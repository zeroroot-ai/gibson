// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — observation_gate.go
//
// The Taxonomy gate on the emit path (ADR-0012). A shape the global Taxonomy
// admits materialises as a typed node; a shape it does not admit is never
// rejected and never lost — it lands as an Observation, immediately queryable,
// with the residue preserved.
//
// Before this, an ObserveRequest variant the daemon did not recognise fell out
// of the bottom of ingestObservation's type switch and was silently dropped.
// That is the failure mode the Observation fallback exists to remove: an agent
// emitting a shape this binary has never heard of — because it is newer than
// the daemon, or because the shape has not been promoted — must still land
// something the operator can see.
package daemon

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// unknownVariantShape is the shape recorded when the emitter set an observation
// variant this binary's descriptor does not know. The payload cannot be walked
// structurally — the fields are not in the descriptor — so the raw bytes are
// preserved instead. Never lost is the requirement; queryable-by-field is not,
// for a shape nobody has defined yet.
const unknownVariantShape = "UnknownObservationVariant"

// maxObservationPayloadEntries bounds how much residue one Observation carries.
// The emit-path caps proper are gibson#1260's; this is the projector-side floor
// that keeps a single malformed message from turning into an unbounded property
// bag on the node.
const maxObservationPayloadEntries = 256

// observationShape names the shape an ObserveRequest is carrying, as the
// Taxonomy would spell it. The generated oneof wrapper for `HostObservation
// host` is ObserveRequest_Host, so the wrapper's type name is the shape.
func observationShape(observation any) string {
	if observation == nil {
		return ""
	}
	name := fmt.Sprintf("%T", observation)
	if i := strings.LastIndex(name, "ObserveRequest_"); i >= 0 {
		return name[i+len("ObserveRequest_"):]
	}
	return strings.TrimPrefix(name, "*")
}

// gateObservation puts an ObserveRequest that no typed handler claimed to the
// global Taxonomy, and returns the Observation it lands as.
//
// It returns ok=false only when there is genuinely nothing to record — an
// ObserveRequest with no observation set and no unknown bytes on the wire.
// Every other input produces an Observation: the gate never rejects.
//
// eventID is the Observation's identity, minted here because this is where a
// distinct sighting enters the Timeline. It is persisted on the event, so
// replay reproduces the same node, and it is per-sighting rather than
// per-content, so two sightings of the same fact three weeks apart stay
// distinct nodes with a shared content hash.
func gateObservation(req *harnesspb.ObserveRequest, scope, missionID string, now time.Time) (brain.ObservationRecorded, bool) {
	if req == nil {
		return brain.ObservationRecorded{}, false
	}

	shape := observationShape(req.Observation)
	payload := map[string]string{}

	switch {
	case req.Observation != nil:
		flattenObservation(req, payload)
	default:
		// No known variant is set. If the emitter sent bytes this binary's
		// descriptor cannot place, they are a newer shape, not noise — keep
		// them verbatim rather than dropping the emit.
		unknown := req.ProtoReflect().GetUnknown()
		if len(unknown) == 0 {
			return brain.ObservationRecorded{}, false
		}
		shape = unknownVariantShape
		payload["unknown_wire_bytes_b64"] = base64.StdEncoding.EncodeToString(unknown)
		payload["unknown_wire_bytes_len"] = strconv.Itoa(len(unknown))
	}

	// The classification is recorded on the node so an operator can see *why*
	// a shape landed here — and so promoting it later is visibly a Taxonomy
	// change rather than a silent behaviour change.
	decision := taxonomy.Global.ClassifyNode(shape)
	payload["taxonomy_decision"] = decision.Reason
	if decision.InTaxonomy {
		// The shape is promoted but no typed handler claimed it. That is a
		// gap between the Taxonomy and ingestObservation, not an agent error,
		// so it still lands rather than being dropped.
		payload["taxonomy_decision"] = "shape is in Taxonomy but has no typed ingest path"
	}

	return brain.ObservationRecorded{
		EventID:    uuid.NewString(),
		ScopeID:    scope,
		MissionID:  missionID,
		Shape:      shape,
		Payload:    payload,
		ObservedAt: now.UnixMilli(),
	}, true
}

// flattenObservation walks the set observation variant and records its scalar
// fields as residue. Reflection rather than a type switch, because the whole
// point of this path is to handle shapes the switch above it does not.
func flattenObservation(req *harnesspb.ObserveRequest, into map[string]string) {
	msg := req.ProtoReflect()
	oneof := msg.Descriptor().Oneofs().ByName("observation")
	if oneof == nil {
		return
	}
	set := msg.WhichOneof(oneof)
	if set == nil {
		return
	}
	value := msg.Get(set)
	if set.Kind() != protoreflect.MessageKind {
		into[string(set.Name())] = value.String()
		return
	}
	value.Message().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if len(into) >= maxObservationPayloadEntries {
			return false
		}
		// Scalars only. A nested message or list has no single string form
		// worth guessing at, and the count of what was skipped is recorded
		// below so the residue never silently claims to be complete.
		if fd.IsList() || fd.IsMap() || fd.Kind() == protoreflect.MessageKind ||
			fd.Kind() == protoreflect.GroupKind {
			into["skipped_"+string(fd.Name())] = fd.Kind().String()
			return true
		}
		into[string(fd.Name())] = v.String()
		return true
	})
}
