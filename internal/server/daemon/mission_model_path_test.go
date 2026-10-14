// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// mission_model_path_test.go — gibson#1193: a mission uses the model that the
// tenant saved, and never asks the provider for a model list. These tests run
// the real Anthropic provider through the real adapter and slot manager
// against an httptest fake, and count every request.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

type anthropicFake struct {
	*httptest.Server
	listCalls atomic.Int32
	messages  atomic.Int32
	lastModel atomic.Value
}

func newAnthropicFake(t *testing.T) *anthropicFake {
	t.Helper()
	f := &anthropicFake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			f.listCalls.Add(1)
			w.WriteHeader(http.StatusInternalServerError) // the list is down
			_, _ = w.Write([]byte(`{"error":{"message":"list is down"}}`))
			return
		}
		f.messages.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		f.lastModel.Store(req.Model)
		_, _ = w.Write([]byte(`{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	t.Cleanup(f.Close)
	return f
}

// missionAdapter wires the adapter to one tenant set that holds the provider.
func missionAdapter(t *testing.T, p llm.LLMProvider) *component.LLMRegistryAdapter {
	t.Helper()
	reg := llm.NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(p))
	sm := NewDaemonSlotManager(reg, slog.New(slog.DiscardHandler)).WithDefaultProvider(p.Name())
	return component.NewLLMRegistryAdapter(nil, nil, nil).WithTenantResolver(
		func(context.Context, string) (llm.SlotManager, llm.LLMRegistry, error) { return sm, reg, nil })
}

const missionMessages = `[{"role":"user","content":"hi"}]`

func TestMission_UsesTheSavedModelAndNeverListsModels(t *testing.T) {
	fake := newAnthropicFake(t)
	p, err := providers.NewAnthropicProvider(llm.ProviderConfig{
		APIKey: "k", DefaultModel: "claude-saved", BaseURL: fake.URL, AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)
	adapter := missionAdapter(t, p)

	// "anthropic" names a provider of the tenant, so the slot pins it. A name
	// that is not a provider ("primary") resolves through the tenant default.
	for _, slot := range []string{"anthropic", "primary"} {
		content, _, _, _, _, err := adapter.Complete(context.Background(), "acme", "m1", slot, missionMessages, 16, 0)
		require.NoError(t, err, "slot %s", slot)
		assert.Equal(t, "pong", content)
		assert.Equal(t, "claude-saved", fake.lastModel.Load(), "the saved default model serves the mission")
	}
	assert.Zero(t, fake.listCalls.Load(), "a mission must not call the list endpoint, even when it is down")
}

func TestMission_ProviderWithNoSavedModelFailsClearly(t *testing.T) {
	fake := newAnthropicFake(t)
	p, err := providers.NewAnthropicProvider(llm.ProviderConfig{APIKey: "k", BaseURL: fake.URL, AllowPrivateEndpoint: true})
	require.NoError(t, err)
	adapter := missionAdapter(t, p)

	_, _, _, _, _, err = adapter.Complete(context.Background(), "acme", "m1", "anthropic", missionMessages, 16, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no saved default model")
	assert.Zero(t, fake.listCalls.Load(), "no list call, even to find a model")
	assert.Zero(t, fake.messages.Load(), "no completion is sent without a model")
}

func TestMission_ListOutageDoesNotBreakAMissionOnAWindowlessProvider(t *testing.T) {
	// B1: the primary slot has a 100000 minimum. A provider whose list reports
	// no window must still resolve, because the mission never reads the list.
	fake := newAnthropicFake(t)
	p, err := providers.NewAnthropicProvider(llm.ProviderConfig{
		APIKey: "k", DefaultModel: "claude-saved", BaseURL: fake.URL, AllowPrivateEndpoint: true,
	})
	require.NoError(t, err)
	reg := llm.NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(p))
	sm := NewDaemonSlotManager(reg, slog.New(slog.DiscardHandler))

	for _, name := range []string{"primary", "fast", "vision", "reasoning"} {
		provider, model, err := sm.ResolveSlot(context.Background(), newSlot(name), nil)
		require.NoError(t, err, name)
		assert.Equal(t, "anthropic", provider.Name())
		assert.Equal(t, "claude-saved", model.Name)
	}
	assert.Zero(t, fake.listCalls.Load())
}

func newSlot(name string) agent.SlotDefinition { return agent.SlotDefinition{Name: name} }

// writeFakeServiceAccount writes a service-account key file that the Google
// auth library accepts without any network call, and points the Application
// Default Credentials at it.
func writeFakeServiceAccount(t *testing.T) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	doc, err := json.Marshal(map[string]string{ //nolint:gosec // a generated throwaway key for a test
		"type":           "service_account",
		"project_id":     "proj",
		"private_key_id": "k1",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   "sa@proj.iam.gserviceaccount.com",
		"client_id":      "1",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(path, doc, 0o600))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

func TestMission_VertexResolvesASlotFromTheSavedModelWithNoList(t *testing.T) {
	writeFakeServiceAccount(t)
	p, err := providers.NewVertexProvider(context.Background(), llm.ProviderConfig{
		DefaultModel: "claude-sonnet-4-5@20250929",
		Extra:        map[string]string{"vertex_project_id": "proj", "vertex_region": "us-east5"},
	})
	require.NoError(t, err)
	reg := llm.NewLLMRegistry()
	require.NoError(t, reg.RegisterProvider(p))
	sm := NewDaemonSlotManager(reg, slog.New(slog.DiscardHandler)).WithDefaultProvider(p.Name())

	provider, model, err := sm.ResolveSlot(context.Background(), newSlot("primary"), nil)
	require.NoError(t, err, "Vertex must resolve a mission slot as it did before")
	assert.Equal(t, "vertex", provider.Name())
	assert.Equal(t, "claude-sonnet-4-5@20250929", model.Name)
}
