// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command belief-trainer fits the belief artifacts of one tenant (ADR-0106,
// ADR-0137, gibson#614). The CronJob that the tenant operator creates for each
// tenant runs it (gibson#616).
//
// One run serves one tenant:
//
//  1. It reads the training data of the tenant from the daemon
//     (GetBeliefTrainingData): the training rows of the World and the outcome
//     count of each enablement edge type.
//  2. It fits the belief-CPT model, with a base model as the structure and the
//     prior, and the Beta
//     posterior of each learned strength: each edge type, each dependency
//     inside a host and the leak of each host variable.
//  3. It stores both artifacts as one new version of the tenant through the
//     daemon (StoreBeliefArtifact). The daemon numbers the version and its
//     quality gate decides whether the version becomes current (gibson#789).
//
// The trainer talks only to the daemon, over SPIFFE mTLS with the SVID of the
// trainer of the tenant. It holds no database credential and opens no data
// store: no Timeline store, no Redis, no Postgres. main_test.go proves that
// the binary imports no Redis client and no Postgres driver.
//
// The base model is the embedded OSS base-v1 (beliefvi.DefaultArtifact),
// unless BELIEF_BASE_MODEL names a model file. The commercial layer ships a
// curated base model that way (gibson#31): a trainer image with the file and
// the variable. The file must be a valid model with the three query variables.
//
// A tenant with no outcome to learn from gets no new version: the trainer
// logs that and exits 0. One exception: with a base model file, a tenant that
// has no current version gets the base as its first version, so a new tenant
// starts on the curated model, not on base-v1.
//
// Usage:
//
//	belief-trainer -tenant <id>
//
// GIBSON_DAEMON_GRPC_ADDRESS names the daemon, and GIBSON_DAEMON_SPIFFE_ID
// names the SVID that the daemon must present. SPIFFE_ENDPOINT_SOCKET names the
// socket of the SPIRE agent. BELIEF_BASE_MODEL names the base model file.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	daemontransport "github.com/zeroroot-ai/gibson/operators/tenant/pkg/transport/daemon"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(context.Background(), os.Args[1:], os.Getenv, dialDaemon, logger); err != nil {
		logger.Error("belief-trainer failed", "error", err)
		os.Exit(1)
	}
}

// trainerClient is the part of the daemon operator API that the trainer
// calls. The generated DaemonOperatorServiceClient satisfies it.
type trainerClient interface {
	GetBeliefTrainingData(
		ctx context.Context, in *daemonoperatorv1.GetBeliefTrainingDataRequest, opts ...grpc.CallOption,
	) (*daemonoperatorv1.GetBeliefTrainingDataResponse, error)
	StoreBeliefArtifact(
		ctx context.Context, in *daemonoperatorv1.StoreBeliefArtifactRequest, opts ...grpc.CallOption,
	) (*daemonoperatorv1.StoreBeliefArtifactResponse, error)
}

// dialFunc opens the trainer client. The returned closer releases it.
type dialFunc func(ctx context.Context, addr, daemonSPIFFEID string) (trainerClient, io.Closer, error)

// dialDaemon opens the SPIFFE mTLS connection to the daemon with the SVID
// that the SPIRE agent issues to this pod.
func dialDaemon(ctx context.Context, addr, daemonSPIFFEID string) (trainerClient, io.Closer, error) {
	c, err := daemontransport.NewClient(ctx, daemontransport.Options{Addr: addr, DaemonSVID: daemonSPIFFEID})
	if err != nil {
		return nil, nil, fmt.Errorf("connect to the daemon: %w", err)
	}
	return daemonoperatorv1.NewDaemonOperatorServiceClient(c.Conn()), c, nil
}

// candidateVersion is the version that the trainer writes into both
// artifacts. The daemon replaces it with the version number it gives the
// stored row.
func candidateVersion(tenant string) string {
	return "tenant-" + tenant + "-candidate"
}

// run parses args against its own FlagSet, so it is a plain function that a
// test calls directly.
func run(ctx context.Context, args []string, getenv func(string) string, dial dialFunc, logger *slog.Logger) error {
	fs := flag.NewFlagSet("belief-trainer", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "the tenant to train (required)")
	addr := fs.String("daemon-addr", getenv("GIBSON_DAEMON_GRPC_ADDRESS"), "the gRPC address of the daemon")
	daemonID := fs.String("daemon-spiffe-id", getenv("GIBSON_DAEMON_SPIFFE_ID"), "the SPIFFE ID that the daemon must present")
	basePath := fs.String("base-model", getenv(BaseModelEnv), "a base model file; empty uses the embedded base-v1")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	switch {
	case strings.TrimSpace(*tenant) == "":
		return errors.New("-tenant is required")
	case strings.TrimSpace(*addr) == "":
		return errors.New("-daemon-addr or GIBSON_DAEMON_GRPC_ADDRESS is required")
	case strings.TrimSpace(*daemonID) == "":
		return errors.New("-daemon-spiffe-id or GIBSON_DAEMON_SPIFFE_ID is required")
	}

	base, err := loadBaseModel(*basePath)
	if err != nil {
		return err
	}

	client, closer, err := dial(ctx, *addr, *daemonID)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()

	data, err := client.GetBeliefTrainingData(ctx, &daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: *tenant})
	if err != nil {
		return fmt.Errorf("read the training data of tenant %s: %w", *tenant, err)
	}
	if len(data.GetRows()) == 0 && len(data.GetEdgeOutcomes()) == 0 {
		if strings.TrimSpace(*basePath) == "" || data.GetHasCurrentVersion() {
			logger.Info("the tenant has no outcome to learn from, no new version", "tenant", *tenant)
			return nil
		}
		logger.Info("the tenant has no version: the base model becomes its first version",
			"tenant", *tenant, "base", base.Version)
	}

	model, edges, err := fitArtifacts(base, data, candidateVersion(*tenant))
	if err != nil {
		return fmt.Errorf("fit the artifacts of tenant %s: %w", *tenant, err)
	}
	stored, err := client.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: *tenant, BeliefModel: model, EdgePosteriors: edges,
	})
	if err != nil {
		return fmt.Errorf("store the artifacts of tenant %s: %w", *tenant, err)
	}
	logger.Info("stored a new belief artifact version",
		"tenant", *tenant, "version", stored.GetVersion(),
		"rows", len(data.GetRows()), "edge_types", len(data.GetEdgeOutcomes()))
	return nil
}

// BaseModelEnv names the base model file of the trainer (gibson#31).
const BaseModelEnv = "BELIEF_BASE_MODEL"

// queryVariables are the three variables each base model must hold: the
// runtime asks them of each host.
var queryVariables = []string{"juicy", "exploitable", "reachable"}

// loadBaseModel returns the embedded base-v1 for an empty path, or the model
// in the file. A file that is not a valid model, or that lacks a query
// variable, is an error: a trainer must not fit on a structure the runtime
// cannot query.
func loadBaseModel(path string) (beliefvi.ModelArtifact, error) {
	if strings.TrimSpace(path) == "" {
		base, err := beliefvi.DefaultArtifact()
		if err != nil {
			return beliefvi.ModelArtifact{}, fmt.Errorf("load the embedded base model: %w", err)
		}
		return base, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return beliefvi.ModelArtifact{}, fmt.Errorf("read the base model %s: %w", path, err)
	}
	art, err := beliefvi.ParseModelArtifact(raw)
	if err != nil {
		return beliefvi.ModelArtifact{}, fmt.Errorf("parse the base model %s: %w", path, err)
	}
	if _, err := beliefvi.NewBeliefModel(art); err != nil {
		return beliefvi.ModelArtifact{}, fmt.Errorf("the base model %s is not valid: %w", path, err)
	}
	have := make(map[string]bool, len(art.Variables))
	for _, v := range art.Variables {
		have[v] = true
	}
	for _, q := range queryVariables {
		if !have[q] {
			return beliefvi.ModelArtifact{}, fmt.Errorf("the base model %s has no %q variable", path, q)
		}
	}
	return art, nil
}

// fitArtifacts fits both artifacts from the training data on the base model
// and returns them as JSON documents.
func fitArtifacts(base beliefvi.ModelArtifact, data *daemonoperatorv1.GetBeliefTrainingDataResponse, version string) (model, edges []byte, err error) {
	rows := make([]fit.Row, 0, len(data.GetRows()))
	for _, r := range data.GetRows() {
		rows = append(rows, fit.Row(r.GetVars()))
	}
	fitted, err := fit.Fit(base, rows, version)
	if err != nil {
		return nil, nil, fmt.Errorf("fit the belief model: %w", err)
	}

	counts := make(map[string]fit.OutcomeCount, len(data.GetEdgeOutcomes()))
	for _, c := range data.GetEdgeOutcomes() {
		counts[c.GetEdgeType()] = fit.OutcomeCount{Successes: c.GetAlpha(), Failures: c.GetBeta()}
	}
	posteriors, err := fit.EdgePosteriors(counts, version)
	if err != nil {
		return nil, nil, fmt.Errorf("fit the edge posteriors: %w", err)
	}
	// A row is the evidence of one host, so the rows fit the in-node strengths
	// and the leaks of the Host node type (gibson#720).
	for _, schema := range ontology.SeedBeliefSchemaExtension().Nodes {
		if schema.NodeType == ontology.HostNodeType {
			posteriors.InNode, posteriors.Leaks = fit.NodeStrengths(rows, schema)
		}
	}
	if err := posteriors.Validate(); err != nil {
		return nil, nil, fmt.Errorf("fit the node strengths: %w", err)
	}

	if model, err = json.Marshal(fitted); err != nil {
		return nil, nil, fmt.Errorf("encode the belief model: %w", err)
	}
	if edges, err = json.Marshal(posteriors); err != nil {
		return nil, nil, fmt.Errorf("encode the edge posteriors: %w", err)
	}
	return model, edges, nil
}
