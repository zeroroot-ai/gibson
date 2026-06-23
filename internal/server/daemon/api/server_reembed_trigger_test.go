package api

// server_reembed_trigger_test.go — unit tests for the per-tenant re-embed
// trigger wiring (gibson#940). The trigger fires the heavy re-embed job
// asynchronously when a provider-config write changes a tenant's embedding
// config; these tests stub the trigger so no Redis / embedder work runs and
// assert (a) the provider-config handlers fire it for the right tenant when the
// provider serves embeddings, (b) they do NOT fire it for non-embedding writes,
// and (c) the production ReembedJobTrigger serialises per tenant and runs
// detached.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// stubReembedTrigger records the tenants it was asked to reconcile.
type stubReembedTrigger struct {
	mu       sync.Mutex
	tenants  []string
	fireWait chan struct{} // optional: closed-signal per call when set
}

func (s *stubReembedTrigger) Trigger(tenantID string) {
	s.mu.Lock()
	s.tenants = append(s.tenants, tenantID)
	s.mu.Unlock()
}

func (s *stubReembedTrigger) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.tenants))
	copy(out, s.tenants)
	return out
}

// embeddingInput returns a provider input that declares the embedding capability
// with a known-dimension model (so validateEmbeddingCapability passes).
func embeddingInput(name string) *tenantv1.ProviderConfigInput {
	return &tenantv1.ProviderConfigInput{
		Name:                  name,
		Type:                  "openai",
		DefaultModel:          "gpt-4o-mini",
		Credentials:           map[string]string{"api_key": "sk-test"},
		Capabilities:          []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
		DefaultEmbeddingModel: "text-embedding-3-small",
	}
}

func TestCreateProvider_EmbeddingProvider_FiresReembedForTenant(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("openai")}
	trigger := &stubReembedTrigger{}
	s := serverWithStore(store).WithReembedTrigger(trigger)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: embeddingInput("openai"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, trigger.calls(),
		"an embedding-capable provider create must reconcile the tenant's vector index")
}

func TestCreateProvider_NonEmbeddingProvider_DoesNotFireReembed(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("openai")}
	trigger := &stubReembedTrigger{}
	s := serverWithStore(store).WithReembedTrigger(trigger)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         "openai",
			Type:         "openai",
			DefaultModel: "gpt-4o-mini",
			Credentials:  map[string]string{"api_key": "sk-test"},
			// No embedding capability.
		},
	})
	require.NoError(t, err)
	assert.Empty(t, trigger.calls(),
		"a chat-only provider create must not trigger a re-embed")
}

func TestUpdateProvider_EmbeddingProvider_FiresReembedForTenant(t *testing.T) {
	store := &mockProviderStore{updateOut: fakeProviderRecord("openai")}
	trigger := &stubReembedTrigger{}
	s := serverWithStore(store).WithReembedTrigger(trigger)

	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
		Name:  "openai",
		Input: embeddingInput("openai"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, trigger.calls())
}

func TestSetDefaultProvider_FiresReembedUnconditionally(t *testing.T) {
	// Flipping the default can change the resolved embedder even though this RPC
	// carries no embedding input, so the trigger fires regardless.
	store := &mockProviderStore{getOut: fakeProviderRecord("openai")}
	trigger := &stubReembedTrigger{}
	s := serverWithStore(store).WithReembedTrigger(trigger)

	_, err := s.SetDefaultProvider(tenantCtx("acme"), &tenantv1.SetDefaultProviderRequest{Name: "openai"})
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, trigger.calls())
}

func TestCreateProvider_DefaultNoopTrigger_NoPanic(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("openai")}
	s := serverWithStore(store) // no trigger wired — defaults to the no-op
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: embeddingInput("openai"),
	})
	require.NoError(t, err, "the default no-op trigger must let provider writes succeed, not panic")
}

// ---------------------------------------------------------------------------
// ReembedJobTrigger (production implementation)
// ---------------------------------------------------------------------------

func TestReembedJobTrigger_RunsRunnerForTenant(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
		done = make(chan struct{}, 1)
	)
	runner := func(_ context.Context, tenantID string) error {
		mu.Lock()
		seen = append(seen, tenantID)
		mu.Unlock()
		done <- struct{}{}
		return nil
	}
	tr := NewReembedJobTrigger(runner, nil, time.Minute)

	tr.Trigger("acme")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runner was not invoked within the timeout")
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"acme"}, seen)
}

func TestReembedJobTrigger_SerialisesPerTenant(t *testing.T) {
	// A second Trigger for the same tenant while the first is in flight is deduped.
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var calls int
	var mu sync.Mutex
	runner := func(_ context.Context, _ string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		started <- struct{}{}
		<-release // block so the first run is still "in flight"
		return nil
	}
	tr := NewReembedJobTrigger(runner, nil, time.Minute)

	tr.Trigger("acme")
	<-started // first run is now in flight and blocked

	tr.Trigger("acme") // deduped — must NOT start a second concurrent run

	// Give a deduped run no chance to start.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	got := calls
	mu.Unlock()
	assert.Equal(t, 1, got, "concurrent re-embed for the same tenant must be deduped")

	close(release) // let the first run finish
}

func TestReembedJobTrigger_DifferentTenantsRunConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan string, 2)
	runner := func(_ context.Context, tenantID string) error {
		started <- tenantID
		<-release
		return nil
	}
	tr := NewReembedJobTrigger(runner, nil, time.Minute)

	tr.Trigger("acme")
	tr.Trigger("globex")

	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case tid := <-started:
			seen[tid] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of 2 tenant runs started", len(seen))
		}
	}
	assert.True(t, seen["acme"] && seen["globex"],
		"distinct tenants must reconcile concurrently")
	close(release)
}

func TestReembedJobTrigger_NilSafe(t *testing.T) {
	// A zero-value (nil) trigger is a defensive shim — Trigger is a no-op, never panics.
	var tr *ReembedJobTrigger
	assert.NotPanics(t, func() { tr.Trigger("acme") })

	// A trigger built with a real runner skips the empty-tenant case in the request
	// path (no nil-dep guard — the runner is validated at construction).
	noop := func(context.Context, string) error { return nil }
	tr2 := NewReembedJobTrigger(noop, nil, 0)
	assert.NotPanics(t, func() { tr2.Trigger("") })
}

func TestNewReembedJobTrigger_NilRunnerPanics(t *testing.T) {
	// A nil runner is a wiring bug — validate-at-construction ([[0003]]), so it
	// panics rather than silently no-op'ing in the request path.
	assert.Panics(t, func() { NewReembedJobTrigger(nil, nil, 0) })
}
