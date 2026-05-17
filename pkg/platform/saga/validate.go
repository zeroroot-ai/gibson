package saga

import (
	"fmt"
	"sort"
	"strings"
)

// ValidationError is returned by ValidateAtStartup when one or more steps
// declare RequiredClients() that the provided Deps does not satisfy. The
// error aggregates ALL missing capabilities and lists every step that
// requires each — so the operator's startup log shows the full picture
// in a single message instead of fixing one missing client at a time
// across multiple restarts.
type ValidationError struct {
	// Missing maps each unsatisfied capability to the names of steps that
	// require it.
	Missing map[ClientCapability][]string
}

func (e *ValidationError) Error() string {
	if len(e.Missing) == 0 {
		return "saga: no missing capabilities (this should not happen)"
	}
	caps := make([]ClientCapability, 0, len(e.Missing))
	for c := range e.Missing {
		caps = append(caps, c)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })

	var sb strings.Builder
	sb.WriteString("saga: missing required client capabilities:\n")
	for _, c := range caps {
		steps := e.Missing[c]
		sort.Strings(steps)
		fmt.Fprintf(&sb, "  - capability %q required by step(s): %s\n", c, strings.Join(steps, ", "))
	}
	return strings.TrimRight(sb.String(), "\n")
}

// ValidateAtStartupVerbose validates the step graph + deps and returns
// a one-line success summary suitable for the operator's startup log.
// On failure it returns the same *ValidationError that ValidateAtStartup
// returns; the summary string in that case is empty.
//
// Use this from cmd/main.go so production-mode startup logs explicitly
// state "validated N steps, all M capabilities satisfied" instead of
// leaving operators to infer success from absence-of-error.
//
// The dev-mode bypass parameter was deleted as part of the one-code-path
// epic (deploy#205): the operator binary boots identically in every
// environment; capability misses always fail-fast.
func ValidateAtStartupVerbose(steps []Step, deps *Deps) (summary string, err error) {
	if err := ValidateAtStartup(steps, deps); err != nil {
		return "", err
	}
	// Capability count for the summary: distinct capabilities required
	// by any step.
	required := map[ClientCapability]struct{}{}
	for _, s := range steps {
		for _, c := range s.RequiredClients() {
			required[c] = struct{}{}
		}
	}
	return fmt.Sprintf("saga: validated %d step(s), all %d capabilit(ies) satisfied",
		len(steps), len(required)), nil
}

// ValidateAtStartup checks that every capability listed in any step's
// RequiredClients() is satisfied by deps. Any unsatisfied capability
// returns a *ValidationError aggregating every missing capability and the
// steps that require it.
//
// Topology problems (unknown step references, cycles) are also reported
// here so a misconfigured operator pod fails to start instead of silently
// producing a broken DAG.
//
// The dev-mode bypass parameter was deleted as part of the one-code-path
// epic (deploy#205): one binary, every environment, capability misses
// always fail-fast.
func ValidateAtStartup(steps []Step, deps *Deps) error {
	// Topology check is mandatory — a cyclic graph is a code bug, not a
	// configuration problem.
	if _, err := TopoSort(steps); err != nil {
		return fmt.Errorf("saga: invalid step graph: %w", err)
	}

	missing := map[ClientCapability][]string{}
	for _, s := range steps {
		for _, c := range s.RequiredClients() {
			if !deps.Has(c) {
				missing[c] = append(missing[c], s.Name())
			}
		}
	}
	if len(missing) > 0 {
		return &ValidationError{Missing: missing}
	}
	return nil
}
