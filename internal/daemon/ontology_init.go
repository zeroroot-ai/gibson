package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/ontology"
)

// initOntologyReasoner constructs the ontology Reasoner, registers its
// Prometheus metrics with the daemon's registerer, and loads the core SDK
// vocabulary via Loader.LoadCore. It stores the live reasoner on d.reasoner
// so downstream services (IntelligenceService, ComponentService) can reach it.
//
// Failure to load individual ontology files is non-fatal and is logged at WARN
// level (matching the Loader's own error policy). The method returns an error
// only if the Metrics registration itself fails (which indicates a duplicate
// registration and is a programming error).
//
// Call site: newInfrastructure, after the metricsRegisterer is confirmed to be
// non-nil (it is always set in New via the default or WithMetricsRegisterer).
func (d *daemonImpl) initOntologyReasoner(ctx context.Context) (*ontology.Reasoner, error) {
	// Construct metrics collectors (unregistered; caller must register).
	metrics := ontology.NewMetrics()
	if err := metrics.Register(d.metricsRegisterer); err != nil {
		// A registration error typically means the collectors are already
		// registered (e.g. two daemons sharing prometheus.DefaultRegisterer in
		// a test). Treat as a hard error to surface the bug early.
		return nil, fmt.Errorf("ontology: register prometheus metrics: %w", err)
	}

	// Construct reasoner with metrics wired in.
	r := ontology.NewReasoner(metrics)

	// Construct loader backed by the new reasoner.
	loader := ontology.NewLoader(r, d.logger.Slog())

	// Load the embedded SDK vocabulary. Individual file errors are logged
	// inside LoadCore and do not abort startup.
	if err := loader.LoadCore(); err != nil {
		// LoadCore only returns an error when zero YAML files were found AND
		// the ontology directory existed. This is non-fatal — a sparse or
		// empty SDK ontology should not prevent the daemon from starting.
		d.logger.Warn(ctx, "ontology: LoadCore returned an error; reasoner will be empty",
			"error", err)
	}

	d.logger.Info(ctx, "ontology reasoner initialized")
	return r, nil
}
