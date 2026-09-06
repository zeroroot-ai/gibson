// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package v1alpha1

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestAgentEnrollmentStatus_EveryFieldHasAWriter guards the defect in
// gibson#1188: AgentEnrollment declared BootstrapSecretRef, BootstrapExpiresAt,
// HostID, LastHeartbeat and a BootstrapReady phase that no controller ever
// wrote, while reporting Ready=True throughout. A status field nothing writes is
// worse than a missing one — a reader builds against a promise the resource
// never keeps, and the failure is silent.
//
// The check is deliberately source-level rather than behavioural: it catches a
// field added to the type without a writer, which is exactly how the last four
// got in.
func TestAgentEnrollmentStatus_EveryFieldHasAWriter(t *testing.T) {
	operatorSrc := readOperatorSources(t)

	st := reflect.TypeOf(AgentEnrollmentStatus{})
	for i := range st.NumField() {
		name := st.Field(i).Name
		// Conditions is written through meta.SetStatusCondition, not by
		// assignment, so match the field name anywhere in the operator sources.
		if !strings.Contains(operatorSrc, "Status."+name) {
			t.Errorf("AgentEnrollmentStatus.%s is declared but nothing in operators/tenant writes it; "+
				"either populate it or remove it (gibson#1188)", name)
		}
	}
}

// TestAgentEnrollmentPhases_AreReachable guards the other half: BootstrapReady
// was an enum value the state machine could never enter, so `kubectl explain`
// described a lifecycle step that does not exist.
func TestAgentEnrollmentPhases_AreReachable(t *testing.T) {
	operatorSrc := readOperatorSources(t)

	phases := []AgentEnrollmentPhase{
		AgentEnrollmentPhasePending,
		AgentEnrollmentPhaseActive,
		AgentEnrollmentPhaseRevoked,
		AgentEnrollmentPhaseFailed,
		AgentEnrollmentPhaseTerminated,
	}
	for _, p := range phases {
		if !strings.Contains(operatorSrc, string(p)) {
			t.Errorf("phase %q appears nowhere in operators/tenant outside its own declaration; "+
				"an unreachable phase describes a lifecycle the controller does not have", p)
		}
	}
}

// TestAgentEnrollmentDoc_NamesTheCredentialSource keeps the CRD honest about
// where a component's bootstrap credential comes from. Without it, the resource
// reads as a Kubernetes-native issuance path (ADR-0045 says it is not).
func TestAgentEnrollmentDoc_NamesTheCredentialSource(t *testing.T) {
	src, err := os.ReadFile("agentenrollment_types.go")
	if err != nil {
		t.Fatalf("read types: %v", err)
	}
	if !strings.Contains(string(src), "gibson agent enroll") {
		t.Error("the AgentEnrollment doc comment must name where the bootstrap credential comes from")
	}
}

// readOperatorSources concatenates the operator's non-test, non-generated Go
// sources plus the type declarations, so a field's declaration alone does not
// count as a writer.
func readOperatorSources(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	declOnly := regexp.MustCompile(`agentenrollment_types\.go$|zz_generated`)
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || declOnly.MatchString(path) {
			return nil
		}
		content, readErr := os.ReadFile(path) //nolint:gosec // path comes from walking this repo's own tree
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		b.Write(content)
		return nil
	})
	if err != nil {
		t.Fatalf("walk operator sources: %v", err)
	}
	if b.Len() == 0 {
		t.Fatal("read no operator sources; the walk root is wrong")
	}
	return b.String()
}
