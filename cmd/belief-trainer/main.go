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
//  2. It fits the belief-CPT model, with the embedded OSS base model
//     (beliefvi.DefaultArtifact) as the structure and the prior, and the Beta
//     posterior of each edge type.
//  3. It stores both artifacts as one new version of the tenant through the
//     daemon (StoreBeliefArtifact). The daemon numbers the version and its
//     quality gate decides whether the version becomes current (gibson#789).
//
// The trainer talks only to the daemon, over SPIFFE mTLS with the SVID of the
// trainer of the tenant. It holds no database credential and opens no data
// store: no Timeline store, no Redis, no Postgres. main_test.go proves that
// the binary imports no Redis client and no Postgres driver.
//
// A tenant with no outcome to learn from gets no new version: the trainer
// logs that and exits 0.
//
// Usage:
//
//	belief-trainer -tenant <id>
//
// GIBSON_DAEMON_GRPC_ADDRESS names the daemon, and GIBSON_DAEMON_SPIFFE_ID
// names the SVID that the daemon must present. SPIFFE_ENDPOINT_SOCKET names the
// socket of the SPIRE agent.
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

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
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
// calls.
type trainerClient interface {
	GetBeliefTrainingData(ctx context.Context, in *daemonoperatorv1.GetBeliefTrainingDataRequest) (*daemonoperatorv1.GetBeliefTrainingDataResponse, error)
	StoreBeliefArtifact(ctx context.Context, in *daemonoperatorv1.StoreBeliefArtifactRequest) (*daemonoperatorv1.StoreBeliefArtifactResponse, error)
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
	return grpcTrainerClient{c: daemonoperatorv1.NewDaemonOperatorServiceClient(c.Conn())}, c, nil
}

// grpcTrainerClient drops the per-call options of the generated client, so it
// satisfies trainerClient.
type grpcTrainerClient struct {
	c daemonoperatorv1.DaemonOperatorServiceClient
}

func (g grpcTrainerClient) GetBeliefTrainingData(
	ctx context.Context, in *daemonoperatorv1.GetBeliefTrainingDataRequest,
) (*daemonoperatorv1.GetBeliefTrainingDataResponse, error) {
	resp, err := g.c.GetBeliefTrainingData(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("GetBeliefTrainingData: %w", err)
	}
	return resp, nil
}

func (g grpcTrainerClient) StoreBeliefArtifact(
	ctx context.Context, in *daemonoperatorv1.StoreBeliefArtifactRequest,
) (*daemonoperatorv1.StoreBeliefArtifactResponse, error) {
	resp, err := g.c.StoreBeliefArtifact(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("StoreBeliefArtifact: %w", err)
	}
	return resp, nil
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
		logger.Info("the tenant has no outcome to learn from, no new version", "tenant", *tenant)
		return nil
	}

	model, edges, err := fitArtifacts(data, candidateVersion(*tenant))
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

// fitArtifacts fits both artifacts from the training data and returns them as
// JSON documents.
func fitArtifacts(data *daemonoperatorv1.GetBeliefTrainingDataResponse, version string) (model, edges []byte, err error) {
	base, err := beliefvi.DefaultArtifact()
	if err != nil {
		return nil, nil, fmt.Errorf("load the base model: %w", err)
	}
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

	if model, err = json.Marshal(fitted); err != nil {
		return nil, nil, fmt.Errorf("encode the belief model: %w", err)
	}
	if edges, err = json.Marshal(posteriors); err != nil {
		return nil, nil, fmt.Errorf("encode the edge posteriors: %w", err)
	}
	return model, edges, nil
}
