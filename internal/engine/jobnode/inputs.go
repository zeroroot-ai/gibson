// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package jobnode

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"google.golang.org/protobuf/proto"
)

// FindingsOpen is what a job node writes in JobSpec.inputs to mean "the open
// findings on the target this run is against".
//
// A fix job cannot name finding ids. The mission definition is written before
// the run, and the run is what produces the findings, so the only way to put an
// id in a definition is to have run once and pasted it in — which is a mock, not
// a demo. Before this, ClosedJob.Inputs was JobSpec.inputs verbatim and nothing
// populated it at run time, so fixedByEvents had nothing to keep and the
// FIXED_BY edge never fired on a real run (gibson#497).
//
// The reference resolves server-side, from the run's own target. A caller that
// could name arbitrary ids could point a fix job at findings it was never
// granted; naming no id at all is what makes that impossible. It is the same
// rule CONTEXT.md states for ScopeID, and the same shape as the {{target.*}}
// bindings (gibson#495), in its own namespace.
const FindingsOpen = "{{findings.open}}"

// FindingsResolver answers which of a tenant's findings a job may start from.
type FindingsResolver interface {
	// OpenFindings returns the ids of the tenant's open findings on the target
	// the named mission run is against.
	//
	// An empty result is not an error: a target with nothing open is a target
	// with nothing to fix, and the job opens with no inputs and closes having
	// linked nothing. That is different from an input that was never resolved,
	// which is refused.
	OpenFindings(ctx context.Context, tenant, missionRunID string) ([]string, error)
}

// FindingsResolverFunc adapts a function to FindingsResolver.
type FindingsResolverFunc func(ctx context.Context, tenant, missionRunID string) ([]string, error)

// OpenFindings implements FindingsResolver.
func (f FindingsResolverFunc) OpenFindings(ctx context.Context, tenant, missionRunID string) ([]string, error) {
	return f(ctx, tenant, missionRunID)
}

// resolveInputs returns spec with every reference in its inputs replaced by the
// ids it stands for.
//
// A spec whose inputs hold no reference is returned unchanged. A reference with
// no resolver, or one this package does not know, is an error: the inputs are
// what a fix job's whole correlation rests on, and an unresolved one that
// reached the job would be carried to close as a World node id that names
// nothing, where fixedByEvents would drop it and the edge would go missing in
// silence. That silence is the defect.
func resolveInputs(ctx context.Context, in Input, spec *jobpb.JobSpec) (*jobpb.JobSpec, error) {
	inputs := spec.GetInputs()
	if !hasReference(inputs) {
		return spec, nil
	}

	out, ok := proto.Clone(spec).(*jobpb.JobSpec)
	if !ok {
		return nil, errors.New("jobnode: clone of the job spec is not a JobSpec")
	}

	resolved := make([]string, 0, len(inputs))
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		resolved = append(resolved, id)
	}

	for _, entry := range inputs {
		switch {
		case strings.TrimSpace(entry) == FindingsOpen:
			if in.Findings == nil {
				return nil, fmt.Errorf("jobnode: node %s asks for %s and this daemon resolves no findings",
					in.NodeID, FindingsOpen)
			}
			ids, err := in.Findings.OpenFindings(ctx, in.TenantID, in.MissionRunID)
			if err != nil {
				return nil, fmt.Errorf("jobnode: node %s: resolve %s: %w", in.NodeID, FindingsOpen, err)
			}
			sort.Strings(ids) // one run of the same World resolves to the same job
			for _, id := range ids {
				add(id)
			}
		case isReference(entry):
			return nil, fmt.Errorf("jobnode: node %s names the unknown input reference %q (known: %s)",
				in.NodeID, entry, FindingsOpen)
		default:
			add(entry)
		}
	}
	out.Inputs = resolved
	return out, nil
}

// isReference reports whether an input entry is a reference rather than an id.
func isReference(entry string) bool {
	e := strings.TrimSpace(entry)
	return strings.HasPrefix(e, "{{") && strings.HasSuffix(e, "}}")
}

func hasReference(inputs []string) bool {
	for _, e := range inputs {
		if isReference(e) {
			return true
		}
	}
	return false
}
