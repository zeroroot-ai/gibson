package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"

	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
)

// --- test doubles ------------------------------------------------------

// fakeSandboxClient implements sandboxed.SandboxClient with configurable
// per-image responses. Each Launch records the image so tests can assert
// multi-image iteration order.
type fakeSandboxClient struct {
	mu       sync.Mutex
	launches []sandboxed.LaunchRequest
	logsByID map[string][]byte
	exitByID map[string]int32
	errOn    map[string]error // image → error returned from Launch
	counter  atomic.Int32
}

func newFakeSandboxClient() *fakeSandboxClient {
	return &fakeSandboxClient{
		logsByID: map[string][]byte{},
		exitByID: map[string]int32{},
		errOn:    map[string]error{},
	}
}

func (f *fakeSandboxClient) Launch(_ context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.launches = append(f.launches, req)
	if err, ok := f.errOn[req.Image]; ok {
		return sandboxed.LaunchResponse{}, err
	}
	id := "sbx-" + req.Image
	f.counter.Add(1)
	return sandboxed.LaunchResponse{SandboxID: id}, nil
}

func (f *fakeSandboxClient) StreamLogs(_ context.Context, sandboxID string) (sandboxed.LogStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &fakeLogStream{data: f.logsByID[sandboxID]}, nil
}

func (f *fakeSandboxClient) Wait(_ context.Context, sandboxID string) (sandboxed.WaitResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sandboxed.WaitResponse{ExitCode: f.exitByID[sandboxID]}, nil
}

func (f *fakeSandboxClient) Kill(_ context.Context, _ string) error { return nil }

// setImageLogs arranges the given image's Launch() to return a sandbox
// whose StreamLogs emits the given bytes and whose Wait returns exitCode.
func (f *fakeSandboxClient) setImageLogs(image string, logs []byte, exitCode int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logsByID["sbx-"+image] = logs
	f.exitByID["sbx-"+image] = exitCode
}

type fakeLogStream struct {
	data []byte
	sent bool
}

func (f *fakeLogStream) Recv() ([]byte, error) {
	if f.sent {
		return nil, io.EOF
	}
	f.sent = true
	return f.data, nil
}
func (f *fakeLogStream) Close() error { return nil }

// newTestRegistryPair returns a miniredis + RedisComponentRegistry pair.
func newTestRegistryPair(t *testing.T) (*miniredis.Miniredis, redis.UniversalClient, component.ComponentRegistry) {
	t.Helper()
	mini, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mini.Close)
	client := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{mini.Addr()}})
	t.Cleanup(func() { _ = client.Close() })
	reg := component.NewRedisComponentRegistry(client, 30*time.Second)
	return mini, client, reg
}

// helpers ---------------------------------------------------------------

func catalogJSON(t *testing.T, entries []runnerCatalogEntry) []byte {
	t.Helper()
	raw, err := json.Marshal(entries)
	require.NoError(t, err)
	return raw
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- construction ------------------------------------------------------

func TestNewCatalogRefresher_ValidatesConfig(t *testing.T) {
	_, client, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()

	cases := map[string]CatalogRefresherConfig{
		"missing redis":    {Registry: reg, SandboxClient: sbx, Images: []string{"i"}},
		"missing registry": {Redis: client, SandboxClient: sbx, Images: []string{"i"}},
		"missing client":   {Redis: client, Registry: reg, Images: []string{"i"}},
		"no images":        {Redis: client, Registry: reg, SandboxClient: sbx},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewCatalogRefresher(cfg)
			assert.Error(t, err)
		})
	}
}

// --- single-image happy path ------------------------------------------

func TestTick_HappyPath_WritesEntries(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()

	// Runner catalog: two tools.
	entries := []runnerCatalogEntry{
		{
			Name: "nmap", Version: "0.1.0", Description: "port scanner",
			Tags: []string{"recon", "network"},
			InputSchema: map[string]any{
				"type":     "object",
				"required": []any{"target"},
			},
			OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
			DefaultParseQuality:   int32(componentpb.ParseQuality_PARSE_QUALITY_STRUCTURED),
			Resources:             resourceHint{VCPU: 2, Memory: "512Mi"},
			DefaultTimeoutSeconds: 300,
		},
		{
			Name: "httpx", Version: "0.1.0", Description: "http probe",
			Tags:                  []string{"recon", "web"},
			InputSchema:           map[string]any{"type": "object"},
			OutputProtoType:       "gibson.graphrag.v1.DiscoveryResult",
			DefaultParseQuality:   int32(componentpb.ParseQuality_PARSE_QUALITY_STRUCTURED),
			Resources:             resourceHint{VCPU: 1, Memory: "256Mi"},
			DefaultTimeoutSeconds: 180,
		},
	}
	sbx.setImageLogs("runner:v0.1", catalogJSON(t, entries), 0)

	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:        []string{"runner:v0.1"},
		SandboxClient: sbx,
		Registry:      reg,
		Redis:         redisClient,
		SelfID:        "self-1",
		Tenant:        "gibson-dev",
		Logger:        silentLogger(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.tick(ctx)

	// Two entries registered.
	nmapInstances, err := reg.DiscoverSystemOnly(ctx, "tool", "nmap")
	require.NoError(t, err)
	require.Len(t, nmapInstances, 1)
	assert.Equal(t, componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED, nmapInstances[0].DispatchMode)
	assert.Equal(t, "runner:v0.1", nmapInstances[0].Image)
	assert.Equal(t, map[string]string{"GIBSON_TOOL_NAME": "nmap"}, nmapInstances[0].Env)
	assert.Equal(t, int32(2), nmapInstances[0].Resources.VCPU)
	assert.Equal(t, "512Mi", nmapInstances[0].Resources.Memory)
	assert.NotEmpty(t, nmapInstances[0].InputSchemaJSON, "input_schema_json should be populated")

	httpxInstances, err := reg.DiscoverSystemOnly(ctx, "tool", "httpx")
	require.NoError(t, err)
	require.Len(t, httpxInstances, 1)
	assert.Equal(t, int32(1), httpxInstances[0].Resources.VCPU)
}

// --- multi-image merge --------------------------------------------------

func TestTick_MultiImage_EarlierImageWins(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()

	// Image A: nmap v0.1.
	sbx.setImageLogs("runner-stable", catalogJSON(t, []runnerCatalogEntry{
		{Name: "nmap", Version: "0.1.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
	}), 0)
	// Image B: nmap v0.2 (newer, but comes later in priority list).
	sbx.setImageLogs("runner-experimental", catalogJSON(t, []runnerCatalogEntry{
		{Name: "nmap", Version: "0.2.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
		{Name: "amass", Version: "0.1.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
	}), 0)

	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:        []string{"runner-stable", "runner-experimental"},
		SandboxClient: sbx,
		Registry:      reg,
		Redis:         redisClient,
		SelfID:        "self-1",
		Logger:        silentLogger(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.tick(ctx)

	// nmap v0.1 (stable) must win over v0.2 (experimental) because stable
	// appears first in Images.
	nmap, err := reg.DiscoverSystemOnly(ctx, "tool", "nmap")
	require.NoError(t, err)
	require.Len(t, nmap, 1)
	assert.Equal(t, "0.1.0", nmap[0].Version)
	assert.Equal(t, "runner-stable", nmap[0].Image)

	// amass is unique to experimental → it lands.
	amass, err := reg.DiscoverSystemOnly(ctx, "tool", "amass")
	require.NoError(t, err)
	require.Len(t, amass, 1)
}

// --- failure modes ------------------------------------------------------

func TestTick_AllImagesFail_PreservesPrevious(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()

	// First tick: success writes nmap.
	sbx.setImageLogs("runner:v0.1", catalogJSON(t, []runnerCatalogEntry{
		{Name: "nmap", Version: "0.1.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
	}), 0)
	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:        []string{"runner:v0.1"},
		SandboxClient: sbx,
		Registry:      reg,
		Redis:         redisClient,
		SelfID:        "self-1",
		Logger:        silentLogger(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.tick(ctx)

	// Second tick: force launch failure for the image.
	sbx.mu.Lock()
	sbx.errOn["runner:v0.1"] = errors.New("dial refused")
	sbx.mu.Unlock()
	r.tick(ctx)

	// nmap must still be there — previous good state preserved.
	entries, err := reg.DiscoverSystemOnly(ctx, "tool", "nmap")
	require.NoError(t, err)
	assert.Len(t, entries, 1, "nmap entry must survive a failed refresh")
}

func TestTick_MalformedCatalog_RejectsImage(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()
	sbx.setImageLogs("runner:bad", []byte("not valid json"), 0)

	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:        []string{"runner:bad"},
		SandboxClient: sbx,
		Registry:      reg,
		Redis:         redisClient,
		SelfID:        "self-1",
		Logger:        slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.tick(ctx)

	// No entries should have been written.
	entries, err := reg.ListTenantComponents(ctx, systemTenant)
	require.NoError(t, err)
	assert.Empty(t, entries, "malformed catalog must not write any entries")
}

// --- leader election ----------------------------------------------------

func TestTryAcquireLeader_FirstWinsSecondDefers(t *testing.T) {
	_, client, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()

	r1, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images: []string{"runner:v0.1"}, SandboxClient: sbx,
		Registry: reg, Redis: client,
		SelfID: "replica-a", Logger: silentLogger(),
	})
	require.NoError(t, err)
	r2, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images: []string{"runner:v0.1"}, SandboxClient: sbx,
		Registry: reg, Redis: client,
		SelfID: "replica-b", Logger: silentLogger(),
	})
	require.NoError(t, err)

	ctx := context.Background()
	ok1, err := r1.tryAcquireLeader(ctx)
	require.NoError(t, err)
	assert.True(t, ok1, "replica-a should acquire the lease")

	ok2, err := r2.tryAcquireLeader(ctx)
	require.NoError(t, err)
	assert.False(t, ok2, "replica-b must not win while replica-a holds lease")

	// replica-a re-acquires: it's the holder, so SetNX returns false but
	// the Get+Expire renewal path returns true.
	ok1again, err := r1.tryAcquireLeader(ctx)
	require.NoError(t, err)
	assert.True(t, ok1again, "replica-a should renew its own lease")
}

// --- start/stop lifecycle ----------------------------------------------

func TestStart_FirstRefreshRunsAsynchronously(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()
	sbx.setImageLogs("runner:v0.1", catalogJSON(t, []runnerCatalogEntry{
		{Name: "nmap", Version: "0.1.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
	}), 0)

	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:          []string{"runner:v0.1"},
		SandboxClient:   sbx,
		Registry:        reg,
		Redis:           redisClient,
		RefreshInterval: 100 * time.Millisecond,
		SelfID:          "self",
		Logger:          silentLogger(),
	})
	require.NoError(t, err)

	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	// Poll up to 2s for the first refresh to land. This guards against
	// flakiness on slow CI.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := reg.DiscoverSystemOnly(context.Background(), "tool", "nmap")
		if err == nil && len(entries) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("first refresh did not populate registry within 2s")
}

func TestRefreshNow_TriggersImmediate(t *testing.T) {
	_, redisClient, reg := newTestRegistryPair(t)
	sbx := newFakeSandboxClient()
	// Long interval so only RefreshNow causes a tick to fire.
	sbx.setImageLogs("runner:v0.1", catalogJSON(t, []runnerCatalogEntry{
		{Name: "nmap", Version: "0.1.0", OutputProtoType: "gibson.graphrag.v1.DiscoveryResult"},
	}), 0)

	r, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:          []string{"runner:v0.1"},
		SandboxClient:   sbx,
		Registry:        reg,
		Redis:           redisClient,
		RefreshInterval: 1 * time.Hour,
		SelfID:          "self",
		Logger:          silentLogger(),
	})
	require.NoError(t, err)

	require.NoError(t, r.Start(context.Background()))
	defer r.Stop()

	// The initial tick in Start fires immediately and should write nmap.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := reg.DiscoverSystemOnly(context.Background(), "tool", "nmap")
		if err == nil && len(entries) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("initial refresh did not populate registry")
}
