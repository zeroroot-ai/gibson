package seam

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// entry is a type-erased description of a registered seam. It carries enough
// information to populate the startup seam-state log without needing the
// concrete type parameter.
type entry struct {
	name       string
	configKnob string
	saasComp   string // the SaaS-only component that fills this seam (human label)
}

// Registry is a single declared list of every seam in the process. It is used
// to drive a **startup seam-state log** that emits, at daemon boot, the
// resolved state (wired vs fail-safe) of every seam so operators can confirm
// at a glance which SaaS components are active.
//
// A Registry holds only the human-readable metadata needed for the startup
// log; the actual type-safe resolution is performed by individual [Seam.Resolve]
// calls. Use [Register] to populate it and [LogStartupState] to emit the table.
type Registry struct {
	mu      sync.RWMutex
	entries []entry
}

// defaultRegistry is the process-wide default Registry. Callers that do not
// need a custom registrar (i.e. virtually all production code) use the package-
// level [Register] and [LogStartupState] functions which operate on this.
var defaultRegistry Registry

// Register adds a seam descriptor to the default Registry. Typically called
// from package init() or daemon wire-up code, once per seam.
//
//   - name is the seam's human-readable identifier (must match the Spec.Name
//     used when constructing the Seam).
//   - configKnob is the env-var that activates the remote implementation.
//   - saasComponent is the human label of the SaaS-only component that fills
//     this seam when the knob is set (e.g. "billing/entitlements-svc").
func Register(name, configKnob, saasComponent string) {
	defaultRegistry.Register(name, configKnob, saasComponent)
}

// LogStartupState emits a structured startup seam-state log for every seam
// registered in the default Registry. Call this once, early in daemon startup,
// after all seams have been resolved.
func LogStartupState(ctx context.Context, logger *slog.Logger) {
	defaultRegistry.LogStartupState(ctx, logger)
}

// Register adds an entry to the Registry. Safe for concurrent use.
func (r *Registry) Register(name, configKnob, saasComponent string) {
	r.mu.Lock()
	r.entries = append(r.entries, entry{
		name:       name,
		configKnob: configKnob,
		saasComp:   saasComponent,
	})
	r.mu.Unlock()
}

// LogStartupState reads each registered seam's config knob and logs the
// resolved state. It does NOT construct implementations — it inspects the env
// var to determine wired vs fail-safe. This is intentionally read-only: the
// actual implementations were already constructed by [Seam.Resolve]; this
// function only reports their expected states for operators.
//
// Output is a single Info-level log with a "seams" key containing a slice of
// per-seam records, so a single grep can surface the entire seam table from
// the daemon's JSON log stream.
func (r *Registry) LogStartupState(ctx context.Context, logger *slog.Logger) {
	r.mu.RLock()
	entries := make([]entry, len(r.entries))
	copy(entries, r.entries)
	r.mu.RUnlock()

	if len(entries) == 0 {
		return
	}

	type seamRecord struct {
		Name     string `json:"name"`
		Knob     string `json:"knob"`
		SaaSComp string `json:"saas_component"`
		State    string `json:"state"`    // "wired" or "fail-safe"
		Endpoint string `json:"endpoint"` // set when wired
	}

	records := make([]seamRecord, 0, len(entries))
	for _, e := range entries {
		endpoint := strings.TrimSpace(os.Getenv(e.configKnob))
		state := "fail-safe"
		if endpoint != "" {
			state = "wired"
		}
		records = append(records, seamRecord{
			Name:     e.name,
			Knob:     e.configKnob,
			SaaSComp: e.saasComp,
			State:    state,
			Endpoint: endpoint,
		})
	}

	// Build a slog.Attr slice so the records appear as a structured array in
	// JSON logs rather than a stringified slice.
	attrs := make([]any, 0, len(records)+1)
	attrs = append(attrs, "count", len(records))
	for _, rec := range records {
		attrs = append(attrs,
			slog.Group(rec.Name,
				slog.String("knob", rec.Knob),
				slog.String("saas_component", rec.SaaSComp),
				slog.String("state", rec.State),
				slog.String("endpoint", rec.Endpoint),
			),
		)
	}
	logger.InfoContext(ctx, "seam startup state", attrs...)
}
