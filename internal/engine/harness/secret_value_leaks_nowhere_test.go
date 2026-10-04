// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

// The guarantee gibson#485 makes, asserted as one property rather than as a
// habit: the VALUE of a declared secret reaches the dispatched tool's
// environment and appears nowhere else.
//
// "Nowhere else" is every surface that outlives the dispatch, and each one is a
// place a value WOULD have ended up under the design this replaced:
//
//   - the mission definition, which is stored, listed, rendered and displayed.
//     The old contract put the kubeconfig in ToolNodeConfig.input.
//   - the tool call's input, which captureToolCall persists with the call.
//   - the mission context, which is serialised into places a component reads.
//   - the log, which is shipped off the box.
//
// The sentinel is deliberately long and distinctive, so a substring match
// cannot miss it and cannot match something else.
const sentinelSecretValue = "SENTINEL-kubeconfig-value-f4c1a9-do-not-store"

func TestSecretValue_ReachesTheToolAndLeaksNowhereElse(t *testing.T) {
	const secretName = "cred:goat-cluster"

	// The definition an author writes: a NAME, under a scope.
	def := &missionv1.MissionDefinition{
		Name: "cluster-assessment",
		Secrets: &missionv1.MissionSecrets{
			Tool: map[string]*missionv1.SecretNames{
				"kube-bench": {Names: []string{secretName}},
			},
		},
		Nodes: map[string]*missionv1.MissionNode{
			"benchmark": {
				Id:   "benchmark",
				Type: missionv1.NodeType_NODE_TYPE_TOOL,
				Config: &missionv1.MissionNode_ToolConfig{ToolConfig: &missionv1.ToolNodeConfig{
					ToolName: "kube-bench",
					Input: map[string]string{
						"target":           "goat",
						"kubeconfigSecret": secretName,
					},
				}},
			},
		},
	}

	var logged bytes.Buffer
	h := &DefaultAgentHarness{
		missionCtx:     MissionContext{Secrets: MissionSecretScopesFromProto(def.GetSecrets())},
		missionSecrets: &stubCreds{values: map[string]string{secretName: sentinelSecretValue}},
		logger:         slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	spec := sandboxed.ToolSpec{}
	if err := h.addDeclaredSecrets(context.Background(), "kube-bench", &spec); err != nil {
		t.Fatalf("addDeclaredSecrets: %v", err)
	}

	// 1. It DOES reach the tool. A test that only checked the absences would
	//    pass on a dispatch that handed the tool nothing at all.
	if got := spec.Env["GIBSON_SECRET_CRED_GOAT_CLUSTER"]; got != sentinelSecretValue {
		t.Fatalf("the tool's environment = %q, want the resolved value", got)
	}

	// 2. The stored definition. Marshalled the way the daemon stores and the
	//    dashboard renders it.
	stored, err := protojson.Marshal(def)
	if err != nil {
		t.Fatalf("marshal the definition: %v", err)
	}
	assertNoSentinel(t, "the stored mission definition", string(stored))
	// And it still carries the NAME, which is what makes a dispatch possible.
	if !strings.Contains(string(stored), secretName) {
		t.Errorf("the definition does not carry the secret's name; nothing could resolve it")
	}

	// 3. The tool call's input, which captureToolCall persists.
	input, err := json.Marshal(def.GetNodes()["benchmark"].GetToolConfig().GetInput())
	if err != nil {
		t.Fatalf("marshal the tool input: %v", err)
	}
	assertNoSentinel(t, "the tool call's stored input", string(input))

	// 4. The mission context, serialised. Secrets carries json:"-" on purpose:
	//    even the NAMES are a hint about what a tenant holds.
	mc, err := json.Marshal(h.Mission())
	if err != nil {
		t.Fatalf("marshal the mission context: %v", err)
	}
	assertNoSentinel(t, "the serialised mission context", string(mc))
	if strings.Contains(string(mc), secretName) {
		t.Errorf("the serialised mission context carries the secret's name: %s", mc)
	}

	// 5. The log.
	assertNoSentinel(t, "the log", logged.String())
}

// A refusal must not print the value either. A store that fails can quote what
// it was handed, so the refusal says the NAME and never the error's own body.
func TestSecretValue_ARefusalDoesNotPrintTheValue(t *testing.T) {
	const secretName = "cred:goat-cluster"

	var logged bytes.Buffer
	h := &DefaultAgentHarness{
		missionCtx: MissionContext{Secrets: MissionSecretScopes{
			Tool: map[string][]string{"kube-bench": {secretName}},
		}},
		missionSecrets: &stubCreds{
			err:    errors.New("openbao refused: " + sentinelSecretValue),
			values: map[string]string{secretName: sentinelSecretValue},
		},
		logger: slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	spec := sandboxed.ToolSpec{}
	err := h.addDeclaredSecrets(context.Background(), "kube-bench", &spec)
	if err == nil {
		t.Fatal("the dispatch was allowed although the store failed")
	}
	assertNoSentinel(t, "the refusal message", err.Error())
	assertNoSentinel(t, "the log", logged.String())
	assertNoSentinel(t, "the tool's environment", mapValues(spec.Env))
	if !strings.Contains(err.Error(), secretName) {
		t.Errorf("the refusal does not name the secret: %v", err)
	}
}

func assertNoSentinel(t *testing.T, where, got string) {
	t.Helper()
	if strings.Contains(got, sentinelSecretValue) {
		t.Errorf("the secret's VALUE appears in %s:\n%s", where, got)
	}
}

func mapValues(m map[string]string) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(v)
		b.WriteString("\n")
	}
	return b.String()
}
