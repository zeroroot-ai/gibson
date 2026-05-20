// Package eviction implements the in-daemon spot-instance eviction drain
// handler. It watches /var/run/aws/spot-interruption-notice (a hostPath
// file written by the aws-node-termination-handler DaemonSet on each
// zero-day.ai/sandbox-host node) and, on notice, gracefully drains all
// in-flight Setec detonations before the 2-minute AWS eviction deadline.
//
// Design: setec-sandbox-prod-default §C7 / §"Spot eviction handling"
// Requirements: NFR-R1
//
// The drain sequence (per the design's sequence diagram):
//  1. Cordon the node (PreferNoSchedule taint) via the Kubernetes API.
//  2. Cancel every registered in-flight detonation context (graceful cancel
//     so Setec can flush and terminate cleanly).
//  3. Mark health state as "degraded" (NOT "down") so the
//     SandboxSpotEvictionStorm alert fires instead of SandboxUnavailable.
//  4. At T+graceWindow (default 90 s), hard-kill any detonation whose
//     cancel returned but whose caller has not yet returned from
//     ExecuteWithSpec.
//  5. At T+hardKillDeadline (default 110 s), hard-cancel any remaining
//     detonation by closing its hard-kill channel.
//
// The handler is NOT a dispatch gate. It never refuses new dispatch
// requests — by the time BeginDrain fires, the node is cordoned so no new
// pods will land here anyway. Existing callers are drained.
//
// Integration:
//
//	handler := eviction.New(eviction.Config{...})
//	// At the top of ExecuteWithSpec:
//	deregister := handler.Register(detonationID, cancel)
//	defer deregister()
//
// BeginDrain is called by the notice watcher goroutine started via Watch().
package eviction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	// DefaultNoticeFile is the hostPath populated by
	// aws-node-termination-handler when a spot-interruption notice arrives.
	DefaultNoticeFile = "/var/run/aws/spot-interruption-notice"

	// DefaultGraceWindow is the time between the cancel broadcast and the
	// hard-kill broadcast. 90 s gives detonations time to flush and exit
	// cleanly before AWS terminates the instance at T+120 s.
	DefaultGraceWindow = 90 * time.Second

	// hardKillDeadline is the offset from drain start at which any
	// detonation that has not exited is force-killed. Must be < 120 s
	// (AWS eviction deadline) and > DefaultGraceWindow.
	hardKillDeadline = 110 * time.Second

	// pollInterval is how frequently Watch polls the notice file when no
	// inotify-equivalent is available. Low-cost: stat(2) is cheap.
	pollInterval = 2 * time.Second
)

// HealthState represents the sandbox health as seen by this package.
// Only the eviction handler sets Degraded; external health probes
// (removed in commit 09dc6e6) previously also wrote this value. The
// three-state model is kept for forward-compatibility with the
// SandboxSpotEvictionStorm alert expression.
type HealthState int

const (
	// HealthUp indicates normal operation.
	HealthUp HealthState = iota
	// HealthDegraded indicates a spot eviction is in progress; existing
	// detonations may be failing, but the sandbox is not fully gone.
	HealthDegraded
	// HealthDown indicates the sandbox is unavailable. Not set by this
	// package; reserved for external health probes.
	HealthDown
)

func (h HealthState) String() string {
	switch h {
	case HealthUp:
		return "up"
	case HealthDegraded:
		return "degraded"
	case HealthDown:
		return "down"
	default:
		return "unknown"
	}
}

// NodeCordonner is a minimal subset of the Kubernetes nodes API surface
// that the handler needs. It is satisfied by a real kubernetes.Interface
// and by the fake client in tests.
type NodeCordonner interface {
	// CordonNode applies the Unschedulable=true taint to the named node.
	CordonNode(ctx context.Context, nodeName string) error
}

// kubeCordonner adapts a kubernetes.Interface to NodeCordonner. It patches
// the node with Unschedulable=true — the standard kubectl cordon operation.
// RBAC: requires nodes/patch on resource "nodes" (nodes/cordon subresource
// maps to the same patch verb in k8s RBAC).
type kubeCordonner struct {
	cs kubernetes.Interface
}

// cordonPatch is the JSON-patch payload for kubectl cordon.
type cordonPatch struct {
	Spec nodeSpec `json:"spec"`
}

type nodeSpec struct {
	Unschedulable bool `json:"unschedulable"`
}

// CordonNode marks the node as Unschedulable via a strategic-merge patch.
func (k *kubeCordonner) CordonNode(ctx context.Context, nodeName string) error {
	payload := cordonPatch{Spec: nodeSpec{Unschedulable: true}}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("eviction: marshal cordon patch: %w", err)
	}
	_, err = k.cs.CoreV1().Nodes().Patch(
		ctx,
		nodeName,
		types.StrategicMergePatchType,
		raw,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("eviction: cordon node %q: %w", nodeName, err)
	}
	return nil
}

// NoopCordonner implements NodeCordonner with no side effects. Used when
// the node name is not known (e.g., dev environment without a cluster).
type NoopCordonner struct{}

func (NoopCordonner) CordonNode(_ context.Context, _ string) error { return nil }

// clock abstracts time operations for testing.
type clock interface {
	Now() time.Time
	// After returns a channel that fires after d. The caller is responsible
	// for draining or discarding the channel when done.
	After(d time.Duration) <-chan time.Time
	// NewTicker returns a channel that ticks at interval d and a stop
	// function. Mirrors time.NewTicker semantics.
	NewTicker(d time.Duration) (<-chan time.Time, func())
}

// realClock delegates to the standard time package.
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (realClock) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Config is the constructor input for Handler.
type Config struct {
	// NodeName is the Kubernetes node name this daemon pod runs on.
	// Sourced from the Downward API (spec.nodeName) at runtime.
	// If empty, the cordon step is skipped (dev environment).
	NodeName string

	// NoticeFile is the path to watch for the spot-interruption notice.
	// Defaults to DefaultNoticeFile when zero.
	NoticeFile string

	// Cordonner applies the cordon operation. Defaults to a real
	// kubeCordonner when KubeClient is provided; to NoopCordonner otherwise.
	Cordonner NodeCordonner

	// KubeClient is used to build a kubeCordonner when Cordonner is nil.
	// Ignored when Cordonner is non-nil.
	KubeClient kubernetes.Interface

	// Logger defaults to slog.Default().
	Logger *slog.Logger

	// clock is injected by tests. Production callers leave it nil.
	clock clock

	// onHealthChange is called each time the health state changes. Used by
	// tests to observe state transitions without polling. Production callers
	// leave it nil.
	onHealthChange func(HealthState)

	// fileExists is injected by tests to simulate notice-file appearance
	// without touching the real filesystem. Production callers leave it nil.
	fileExists func(path string) bool
}

// in-flight tracks a single detonation registered with the handler.
type inFlight struct {
	id       string
	cancel   context.CancelFunc
	hardKill chan struct{} // closed by the hard-kill step
}

// Handler watches for spot-interruption notices and drains in-flight
// detonations gracefully. Safe for concurrent use.
type Handler struct {
	mu        sync.Mutex
	cfg       Config
	clk       clock
	cordonner NodeCordonner
	logger    *slog.Logger
	flying    map[string]*inFlight // keyed by detonation ID
	health    HealthState

	// draining is closed once BeginDrain has been called to prevent
	// multiple concurrent drain attempts.
	draining  chan struct{}
	drainOnce sync.Once
}

// New constructs a Handler. Returns an error only on invalid configuration.
func New(cfg Config) (*Handler, error) {
	if cfg.NoticeFile == "" {
		cfg.NoticeFile = DefaultNoticeFile
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	clk := cfg.clock
	if clk == nil {
		clk = realClock{}
	}

	var cordonner NodeCordonner
	switch {
	case cfg.Cordonner != nil:
		cordonner = cfg.Cordonner
	case cfg.KubeClient != nil && cfg.NodeName != "":
		cordonner = &kubeCordonner{cs: cfg.KubeClient}
	default:
		cordonner = NoopCordonner{}
	}

	fe := cfg.fileExists
	if fe == nil {
		fe = defaultFileExists
	}
	cfg.fileExists = fe

	return &Handler{
		cfg:       cfg,
		clk:       clk,
		cordonner: cordonner,
		logger:    cfg.Logger,
		flying:    make(map[string]*inFlight),
		health:    HealthUp,
		draining:  make(chan struct{}),
	}, nil
}

// defaultFileExists checks whether path exists using os.Stat.
func defaultFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Register records an in-flight detonation and returns a deregister
// function. The caller (executor) MUST defer the returned function to
// ensure cleanup on any return path — including panics — from
// ExecuteWithSpec.
//
//	deregister := handler.Register(detonationID, cancel)
//	defer deregister()
//
// If the handler's drain has already begun, Register immediately cancels
// the provided context and returns a no-op deregister so the caller fails
// fast rather than starting work it cannot complete.
func (h *Handler) Register(detonationID string, cancel context.CancelFunc) (deregister func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If drain is already in flight, cancel immediately.
	select {
	case <-h.draining:
		cancel()
		return func() {}
	default:
	}

	hk := make(chan struct{})
	h.flying[detonationID] = &inFlight{
		id:       detonationID,
		cancel:   cancel,
		hardKill: hk,
	}

	return func() {
		h.mu.Lock()
		delete(h.flying, detonationID)
		h.mu.Unlock()
	}
}

// HardKillChan returns the hard-kill channel for a registered detonation.
// The channel is closed when the hard-kill deadline fires. Callers that
// want to honour the deadline (e.g. blocking on a Wait RPC) can select on
// this channel.
//
// Returns a nil channel (blocks forever) if the detonation ID is not
// registered — safe to select on.
func (h *Handler) HardKillChan(detonationID string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if f, ok := h.flying[detonationID]; ok {
		return f.hardKill
	}
	return nil
}

// Health returns the current health state. Safe for concurrent use.
func (h *Handler) Health() HealthState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.health
}

// BeginDrain initiates the drain sequence. It is idempotent: subsequent
// calls return ErrDrainAlreadyStarted immediately.
//
// The drain sequence blocks the caller until the hard-kill step completes
// (T+hardKillDeadline). Callers should run BeginDrain in a goroutine if
// they want non-blocking behaviour.
//
// graceWindow is the delay between the cancel broadcast and the hard-kill
// broadcast. Pass 0 to use DefaultGraceWindow.
func (h *Handler) BeginDrain(ctx context.Context, graceWindow time.Duration) error {
	started := false
	h.drainOnce.Do(func() {
		close(h.draining)
		started = true
	})
	if !started {
		return ErrDrainAlreadyStarted
	}
	if graceWindow <= 0 {
		graceWindow = DefaultGraceWindow
	}

	logger := h.logger

	// --- Step 1: Cordon the node -------------------------------------------
	if h.cfg.NodeName != "" {
		cordonCtx, cordonCancel := context.WithTimeout(ctx, 10*time.Second)
		defer cordonCancel()
		if err := h.cordonner.CordonNode(cordonCtx, h.cfg.NodeName); err != nil {
			// Non-fatal: log and continue drain even if cordon fails.
			logger.Warn("eviction: node cordon failed; continuing drain",
				"node", h.cfg.NodeName,
				"error", err,
			)
		} else {
			logger.Info("eviction: node cordoned",
				"node", h.cfg.NodeName,
			)
		}
	}

	// --- Step 2: Broadcast graceful cancel & collect in-flight items --------
	h.mu.Lock()
	snapshot := make([]*inFlight, 0, len(h.flying))
	for _, f := range h.flying {
		snapshot = append(snapshot, f)
		f.cancel()
	}
	// Update health state to degraded.
	h.health = HealthDegraded
	if h.cfg.onHealthChange != nil {
		h.cfg.onHealthChange(HealthDegraded)
	}
	h.mu.Unlock()

	logger.Info("eviction: graceful cancel broadcast",
		"in_flight", len(snapshot),
		"grace_window", graceWindow,
	)

	// --- Step 3: Wait for grace window, then close hard-kill channels -------
	graceDone := h.clk.After(graceWindow)
	select {
	case <-graceDone:
	case <-ctx.Done():
		// Parent context cancelled; proceed to hard-kill immediately.
	}

	h.mu.Lock()
	remaining := 0
	for _, f := range snapshot {
		// Only close the channel if the detonation is still registered;
		// detonations that returned normally were already deregistered.
		if _, stillAlive := h.flying[f.id]; stillAlive {
			close(f.hardKill)
			remaining++
		}
	}
	h.mu.Unlock()

	if remaining > 0 {
		logger.Warn("eviction: hard-kill fired",
			"remaining", remaining,
			"deadline", hardKillDeadline,
		)
	} else {
		logger.Info("eviction: all detonations drained within grace window",
			"grace_window", graceWindow,
		)
	}

	return nil
}

// Watch starts a background goroutine that polls cfg.NoticeFile and calls
// BeginDrain when the file appears. The goroutine exits when ctx is
// cancelled or when drain begins (whichever comes first).
//
// Watch is the production entry point; tests drive BeginDrain directly or
// inject a fake fileExists to trigger the watcher.
func (h *Handler) Watch(ctx context.Context) {
	go func() {
		h.logger.Info("eviction: watching for spot-interruption notice",
			"path", h.cfg.NoticeFile,
		)
		tickCh, stopTick := h.clk.NewTicker(pollInterval)
		defer stopTick()
		for {
			select {
			case <-ctx.Done():
				return
			case <-h.draining:
				return
			case <-tickCh:
				if h.cfg.fileExists(h.cfg.NoticeFile) {
					h.logger.Warn("eviction: spot-interruption notice detected",
						"path", h.cfg.NoticeFile,
					)
					// BeginDrain blocks; run in goroutine so we don't stall
					// the ticker loop if it takes time.
					go func() { //nolint:errcheck
						_ = h.BeginDrain(ctx, 0)
					}()
					return
				}
			}
		}
	}()
}

// ErrDrainAlreadyStarted is returned by BeginDrain when a drain is already
// in progress.
var ErrDrainAlreadyStarted = errors.New("eviction: drain already started")

// NodeTaint builds the corev1.Taint that the cordon operation applies.
// Exported for use by callers that need to create pre-tainted node objects
// in tests.
func NodeTaint() corev1.Taint {
	return corev1.Taint{
		Key:    "node.kubernetes.io/unschedulable",
		Effect: corev1.TaintEffectNoSchedule,
	}
}
