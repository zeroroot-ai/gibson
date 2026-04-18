package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"

	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/harness/sandboxed"
)

// Constants governing catalog-refresh cadence, lease duration, and bounds.
// Configurable fields live on CatalogRefresherConfig; constants here are
// safety floors and shared identifiers.
const (
	// leaderKey is the Redis key holding the current refresh leader's
	// identity. One SET NX holder at a time drives refreshes; followers
	// read the already-written ComponentRegistry entries.
	leaderKey = "tool_catalog:leader"

	// leaderLeaseTTL bounds how long a leader holds the lease without
	// explicit renewal. A crashed leader loses the lease after this window
	// and followers can claim it.
	leaderLeaseTTL = 5 * time.Minute

	// defaultRefreshInterval is the refresh tick when the config leaves
	// RefreshInterval unset.
	defaultRefreshInterval = 10 * time.Minute

	// listToolsTimeout bounds each gibson-runner --list-tools microVM
	// launch + stdout-marker extraction.
	listToolsTimeout = 30 * time.Second

	// entryTTL is the TTL applied to each ComponentRegistry entry we
	// write. Sized at 2× the refresh interval plus slack so a skipped
	// tick doesn't expire a tool mid-mission.
	entryTTLMultiplier = 3

	// systemTenant is the Registry tenant under which sandboxed tool
	// entries are written — matches internal/component/registry.go's
	// _system convention so every tenant can Discover them.
	systemTenant = "_system"

	// catalogInstanceID is the deterministic InstanceID used when writing
	// entries. There's exactly one "live" sandboxed-tool instance per
	// tool name (not N processes like plugins), so a stable ID keeps the
	// Redis key stable across refreshes and dedup works.
	catalogInstanceID = "catalog"
)

// CatalogRefresherConfig carries the inputs to NewCatalogRefresher. All
// fields except Images and a Redis client are optional.
type CatalogRefresherConfig struct {
	// Images is the list of gibson-tool-runner OCI references to poll.
	// Each image is launched with command gibson-runner --list-tools on
	// every refresh tick; catalogs from all images are merged.
	Images []string

	// RefreshInterval is the cadence between refresh ticks. Zero uses the
	// 10-minute default.
	RefreshInterval time.Duration

	// SandboxClient is the Setec gRPC adapter the refresher uses to
	// launch --list-tools microVMs. Injected by the daemon wiring so the
	// refresher has no direct Setec dependency.
	SandboxClient sandboxed.SandboxClient

	// Tenant is the Setec-side tenant label the refresher presents on
	// Launch. Informational — Setec resolves real tenancy from the
	// client cert CN on mTLS.
	Tenant string

	// Registry is the ComponentRegistry the refresher writes to. Follower
	// replicas read from the same registry but never write.
	Registry component.ComponentRegistry

	// Redis is the client used for leader-election SET NX on leaderKey.
	// Must be the same instance ComponentRegistry uses so timing is
	// consistent across replicas.
	Redis redis.UniversalClient

	// SelfID is this replica's unique identifier for leader-election
	// logs. Defaults to a random UUID if empty.
	SelfID string

	// Logger for refresh-cycle events. slog.Default if nil.
	Logger *slog.Logger
}

// CatalogRefresher periodically launches gibson-tool-runner --list-tools
// in a Setec microVM, merges the returned catalogs, and writes one
// ComponentRegistry entry per tool under tenant=_system, kind=tool,
// DispatchMode=SANDBOXED. A Redis lease ensures only one replica at a
// time drives refreshes; followers read the already-written entries.
//
// Safe for concurrent use: Start spawns exactly one loop goroutine.
type CatalogRefresher struct {
	cfg      CatalogRefresherConfig
	interval time.Duration
	entryTTL time.Duration

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	refresh chan struct{} // RefreshNow signal; buffered 1
	stopped chan struct{}
}

// NewCatalogRefresher constructs a refresher. Returns a clear error on
// misconfiguration (nil Redis, nil Registry, nil SandboxClient, empty
// Images) so daemon startup fails loudly rather than running a silent
// no-op refresher.
func NewCatalogRefresher(cfg CatalogRefresherConfig) (*CatalogRefresher, error) {
	if cfg.Redis == nil {
		return nil, errors.New("catalog refresher: Redis client is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("catalog refresher: ComponentRegistry is required")
	}
	if cfg.SandboxClient == nil {
		return nil, errors.New("catalog refresher: SandboxClient is required")
	}
	if len(cfg.Images) == 0 {
		return nil, errors.New("catalog refresher: at least one runner image is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SelfID == "" {
		cfg.SelfID = uuid.NewString()
	}
	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	return &CatalogRefresher{
		cfg:      cfg,
		interval: interval,
		entryTTL: interval * entryTTLMultiplier,
		refresh:  make(chan struct{}, 1),
		stopped:  make(chan struct{}),
	}, nil
}

// Start begins the refresh loop. Returns immediately; the loop runs until
// Stop is called or the context is cancelled. The first refresh fires
// asynchronously so daemon startup is not blocked on Setec being healthy.
func (r *CatalogRefresher) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("catalog refresher: already started")
	}
	r.running = true
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()

	go r.loop(runCtx)
	return nil
}

// Stop signals the loop to exit and blocks until the goroutine has
// returned. Safe to call multiple times.
func (r *CatalogRefresher) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.cancel()
	r.running = false
	r.mu.Unlock()
	<-r.stopped
}

// RefreshNow enqueues an immediate refresh signal. If a refresh is
// already in-flight or queued, the call is a no-op (the queue depth is 1
// because multiple back-to-back refreshes would all read the same
// catalog). Returns nil on successful enqueue, error if the refresher is
// not running.
func (r *CatalogRefresher) RefreshNow(ctx context.Context) error {
	r.mu.Lock()
	running := r.running
	r.mu.Unlock()
	if !running {
		return errors.New("catalog refresher: not running")
	}
	select {
	case r.refresh <- struct{}{}:
	default:
		// already queued
	}
	return nil
}

// loop is the refresh goroutine. Leader-elects via Redis on every tick,
// runs the refresh only if this replica holds the lease, and sleeps for
// interval between ticks.
func (r *CatalogRefresher) loop(ctx context.Context) {
	defer close(r.stopped)

	// Initial refresh immediately after Start so the registry populates
	// as soon as possible.
	r.tick(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		case <-r.refresh:
			r.tick(ctx)
		}
	}
}

// tick runs one refresh cycle: acquire leader lease, and if acquired,
// drive the refresh. Followers that fail to acquire return quickly.
func (r *CatalogRefresher) tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, listToolsTimeout*time.Duration(len(r.cfg.Images))+30*time.Second)
	defer cancel()

	leader, err := r.tryAcquireLeader(ctx)
	if err != nil {
		r.cfg.Logger.WarnContext(ctx, "catalog refresh: leader lease probe failed",
			"error", err,
			"self_id", r.cfg.SelfID,
		)
		return
	}
	if !leader {
		return
	}

	merged, perImageErrors := r.collectCatalog(ctx)
	if len(merged) == 0 && len(perImageErrors) > 0 {
		// All images failed — don't wipe any entries. Preserve last known
		// good catalog until a subsequent tick succeeds.
		r.cfg.Logger.ErrorContext(ctx, "catalog refresh: every image failed; retaining previous catalog",
			"images", r.cfg.Images,
			"errors", perImageErrors,
		)
		return
	}
	if err := r.writeCatalog(ctx, merged); err != nil {
		r.cfg.Logger.ErrorContext(ctx, "catalog refresh: write failed",
			"error", err,
			"entries", len(merged),
		)
		return
	}
	r.cfg.Logger.InfoContext(ctx, "catalog refresh: applied",
		"entries", len(merged),
		"images", len(r.cfg.Images),
	)
}

// tryAcquireLeader runs the Redis SET NX for the lease key. Returns true
// if this replica is the current leader.
func (r *CatalogRefresher) tryAcquireLeader(ctx context.Context) (bool, error) {
	ok, err := r.cfg.Redis.SetNX(ctx, leaderKey, r.cfg.SelfID, leaderLeaseTTL).Result()
	if err != nil {
		return false, err
	}
	if ok {
		return true, nil
	}
	// SetNX returned false: either another replica holds the lease, OR
	// this replica held it and is simply renewing. Compare holder to self.
	holder, err := r.cfg.Redis.Get(ctx, leaderKey).Result()
	if errors.Is(err, redis.Nil) {
		// Lease vanished between SetNX and Get — race. Retry once.
		ok2, err2 := r.cfg.Redis.SetNX(ctx, leaderKey, r.cfg.SelfID, leaderLeaseTTL).Result()
		if err2 != nil {
			return false, err2
		}
		return ok2, nil
	}
	if err != nil {
		return false, err
	}
	if holder == r.cfg.SelfID {
		// Renew our own lease.
		if err := r.cfg.Redis.Expire(ctx, leaderKey, leaderLeaseTTL).Err(); err != nil {
			return true, err
		}
		return true, nil
	}
	return false, nil
}

// imageCatalog is the merged per-image result the refresher feeds writeCatalog.
type imageCatalog struct {
	Image   string
	Entries []runnerCatalogEntry
}

// runnerCatalogEntry mirrors the JSON shape gibson-tool-runner --list-tools
// emits. Kept in sync with
// opensource/gibson-tool-runner/internal/registry/registry.go.
type runnerCatalogEntry struct {
	Name                  string         `json:"name"`
	Version               string         `json:"version"`
	Description           string         `json:"description"`
	Tags                  []string       `json:"tags"`
	InputSchema           map[string]any `json:"input_schema"`
	OutputProtoType       string         `json:"output_proto_type"`
	DefaultParseQuality   int32          `json:"default_parse_quality"`
	Resources             resourceHint   `json:"resources"`
	DefaultTimeoutSeconds int32          `json:"default_timeout_seconds"`
}

type resourceHint struct {
	VCPU   int32  `json:"vcpu"`
	Memory string `json:"memory"`
}

// collectCatalog launches --list-tools for each configured image and
// returns the merged, de-duplicated set keyed by tool name. When two
// images provide the same tool name, the entry from the earlier image in
// cfg.Images wins — this gives operators deterministic override order.
func (r *CatalogRefresher) collectCatalog(ctx context.Context) (map[string]imageToolEntry, map[string]string) {
	merged := make(map[string]imageToolEntry)
	perImageErrors := make(map[string]string)

	for _, image := range r.cfg.Images {
		entries, err := r.listToolsFromImage(ctx, image)
		if err != nil {
			perImageErrors[image] = err.Error()
			r.cfg.Logger.WarnContext(ctx, "catalog refresh: --list-tools failed for image",
				"image", image,
				"error", err,
			)
			continue
		}
		for _, e := range entries {
			if _, seen := merged[e.Name]; seen {
				// Earlier image already claimed this tool name.
				continue
			}
			merged[e.Name] = imageToolEntry{Image: image, Entry: e}
		}
	}
	return merged, perImageErrors
}

type imageToolEntry struct {
	Image string
	Entry runnerCatalogEntry
}

// listToolsFromImage launches the runner with command --list-tools,
// captures stdout, and parses the JSON array. Errors on non-zero exit or
// unparseable stdout.
func (r *CatalogRefresher) listToolsFromImage(ctx context.Context, image string) ([]runnerCatalogEntry, error) {
	launchCtx, cancel := context.WithTimeout(ctx, listToolsTimeout)
	defer cancel()

	launch, err := r.cfg.SandboxClient.Launch(launchCtx, sandboxed.LaunchRequest{
		Image:   image,
		Command: []string{"gibson-runner", "--list-tools"},
		VCPU:    1,
		Memory:  "128Mi",
		Tenant:  r.cfg.Tenant,
		Timeout: listToolsTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("launch: %w", err)
	}
	sandboxID := launch.SandboxID

	// Stream stdout to capture --list-tools JSON.
	stream, err := r.cfg.SandboxClient.StreamLogs(launchCtx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("stream logs: %w", err)
	}
	defer stream.Close()

	var buf []byte
	for {
		chunk, err := stream.Recv()
		if err != nil {
			break
		}
		buf = append(buf, chunk...)
	}

	wait, err := r.cfg.SandboxClient.Wait(launchCtx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("wait: %w", err)
	}
	if wait.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox exited %d (%s)", wait.ExitCode, wait.Reason)
	}

	var catalog []runnerCatalogEntry
	if err := json.Unmarshal(buf, &catalog); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	return catalog, nil
}

// writeCatalog persists merged entries to ComponentRegistry. Each entry
// uses tenant=_system, kind=tool, a deterministic instance ID of
// "catalog", so repeated refreshes overwrite rather than accumulate.
// Tools removed from the new catalog have their Metadata flagged with
// deprecated=true instead of being deleted — in-flight missions that
// reference the old tool still get a clear "deprecated" signal rather
// than a lookup miss.
func (r *CatalogRefresher) writeCatalog(ctx context.Context, merged map[string]imageToolEntry) error {
	// Stable sort so logs diff cleanly across refreshes.
	names := make([]string, 0, len(merged))
	for name := range merged {
		names = append(names, name)
	}
	sort.Strings(names)

	var writeErr error
	for _, name := range names {
		ent := merged[name]
		info := component.ComponentInfo{
			Kind:                  "tool",
			Name:                  ent.Entry.Name,
			Version:               ent.Entry.Version,
			InstanceID:            catalogInstanceID,
			TenantID:              systemTenant,
			StartedAt:             time.Now(),
			LastHeartbeat:         time.Now(),
			DispatchMode:          componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED,
			Image:                 ent.Image,
			Command:               []string{"gibson-runner"},
			Env:                   map[string]string{"GIBSON_TOOL_NAME": ent.Entry.Name},
			Resources:             component.SandboxResources{VCPU: ent.Entry.Resources.VCPU, Memory: ent.Entry.Resources.Memory},
			DefaultTimeoutSeconds: ent.Entry.DefaultTimeoutSeconds,
			OutputProtoType:       ent.Entry.OutputProtoType,
			DefaultParseQuality:   componentpb.ParseQuality(ent.Entry.DefaultParseQuality),
			Description:           ent.Entry.Description,
			Tags:                  ent.Entry.Tags,
			Metadata:              map[string]string{"source": "gibson-tool-runner"},
		}
		if ent.Entry.InputSchema != nil {
			raw, err := json.Marshal(ent.Entry.InputSchema)
			if err == nil {
				info.InputSchemaJSON = raw
			}
		}
		if _, err := r.cfg.Registry.Register(ctx, systemTenant, "tool", ent.Entry.Name, info); err != nil {
			// Continue writing remaining entries even if one fails. Return
			// the first error at the end so the caller logs it.
			if writeErr == nil {
				writeErr = fmt.Errorf("register tool %q: %w", ent.Entry.Name, err)
			}
			r.cfg.Logger.WarnContext(ctx, "catalog refresh: register failed",
				"tool", ent.Entry.Name,
				"error", err,
			)
		}
	}
	return writeErr
}
