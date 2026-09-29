// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command belief-trainer is the offline batch trainer for the belief field
// (ADR-0006, gibson#753) AND for the per-enablement-edge-type Beta posterior
// (ADR-0037 decisions 2 and 5, gibson#395). It fits NEW versioned PER-TENANT
// artifacts from a tenant's recorded outcomes and writes them in the exact
// formats the native Go belief runtime loads (ADR-0005, ADR-0034, gibson#750;
// ADR-0037, gibson#394/#396).
//
// It is strictly OUT-OF-BAND — never the daemon hot path, never online learning
// (that would break deterministic replay). In production the daemon drives the
// in-process library entrypoints (braintrain.TrainTenant,
// braintrain.TrainTenantEdgePosteriors) against the live per-tenant Registry
// on a schedule; this CLI is the standalone/self-hoster + CI-smoke path,
// fitting from JSON input files so it needs neither a daemon nor pgmpy.
//
// The belief-CPT model and the edge-posterior artifact are independent: pass
// -base/-rows to fit one, -edge-outcomes to fit the other, or both to fit
// both in one run (they version and write independently, never colliding —
// braintrain.NextVersion vs braintrain.NextEdgePosteriorVersion).
//
// Usage:
//
//	belief-trainer -tenant acme -base sidecar/belief/models/base-v1.json \
//	    -rows rows.json -edge-outcomes edge-outcomes.json -out sidecar/belief/models
//
// rows.json is a JSON array of {var:bool} objects (one per observed host), e.g.
//
//	[{"reachable":true,"svc_ssh":true,"exploitable":true,"juicy":true}, ...]
//
// edge-outcomes.json is a JSON array of braintrain.EdgeOutcome objects (one per
// recorded cause-active -> effect-observed? instance), e.g.
//
//	[{"edge_type":"RESOLVES_TO","success":true}, {"edge_type":"RESOLVES_TO","success":false}]
//
// Each trained artifact is written to <out>/tenant-<tenant>-v<n>.json (belief-CPT
// model) or <out>/tenant-<tenant>-edges-v<n>.json (edge posteriors) with n one
// past the highest existing per-tenant version of that kind (past versions are
// never reused, so a mission that pinned vN can always re-load it).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "belief-trainer:", err)
		os.Exit(1)
	}
}

// run parses args against a fresh, non-global FlagSet (flag.ContinueOnError,
// never the package-global flag.CommandLine/flag.Parse) so it is a plain,
// directly unit-testable function: no shared flag state across test cases,
// and a bad flag returns an error instead of calling os.Exit through the
// default ExitOnError handling.
func run(args []string) error {
	fs := flag.NewFlagSet("belief-trainer", flag.ContinueOnError)
	var (
		tenant       = fs.String("tenant", "", "tenant id the artifact(s) are trained for (required)")
		base         = fs.String("base", "", "path to the base model artifact (structural template; fits the belief-CPT model when set with -rows)")
		rows         = fs.String("rows", "", "path to a JSON array of training rows {var:bool} (fits the belief-CPT model when set with -base)")
		edgeOutcomes = fs.String("edge-outcomes", "", "path to a JSON array of braintrain.EdgeOutcome (fits the per-edge-type Beta posterior, gibson#395)")
		out          = fs.String("out", ".", "output directory for the versioned per-tenant artifact(s)")
	)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("belief-trainer: parse flags: %w", err)
	}

	if *tenant == "" {
		fs.Usage()
		return errors.New("-tenant is required")
	}
	trainCPT := *base != "" || *rows != ""
	if trainCPT && (*base == "" || *rows == "") {
		fs.Usage()
		return errors.New("-base and -rows must be given together")
	}
	if !trainCPT && *edgeOutcomes == "" {
		fs.Usage()
		return errors.New("give -base/-rows, -edge-outcomes, or both")
	}

	if trainCPT {
		if err := runCPTTraining(*tenant, *base, *rows, *out); err != nil {
			return err
		}
	}
	if *edgeOutcomes != "" {
		if err := runEdgePosteriorTraining(*tenant, *edgeOutcomes, *out); err != nil {
			return err
		}
	}
	return nil
}

func runCPTTraining(tenant, base, rows, out string) error {
	baseArtifact, err := braintrain.LoadArtifact(base)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, v := range baseArtifact.Variables {
		known[v] = true
	}

	trainingRows, err := loadRows(rows, known)
	if err != nil {
		return err
	}

	version := braintrain.NextVersion(out, tenant)
	trained, err := braintrain.Fit(baseArtifact, trainingRows, version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o750); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	path := out + "/" + version + ".json"
	if err := trained.Write(path); err != nil {
		return err
	}
	fmt.Printf("trained %s from %d rows -> %s\n", version, len(trainingRows), path)
	return nil
}

func runEdgePosteriorTraining(tenant, edgeOutcomesPath, out string) error {
	outcomes, err := loadEdgeOutcomes(edgeOutcomesPath)
	if err != nil {
		return err
	}
	res, err := braintrain.TrainTenantEdgePosteriors(tenant, outcomes, out)
	if err != nil {
		return fmt.Errorf("train edge posteriors: %w", err)
	}
	fmt.Printf("trained %s from %d recorded outcomes -> %s\n", res.Version, res.Outcomes, res.Path)
	return nil
}

// loadRows decodes the training-rows JSON, restricting each row to the variables
// the base network declares (a row only sets columns the model can use).
func loadRows(path string, known map[string]bool) ([]braintrain.Row, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rows: %w", err)
	}
	var raw []map[string]bool
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode rows: %w", err)
	}
	out := make([]braintrain.Row, 0, len(raw))
	for _, r := range raw {
		row := braintrain.Row{}
		for k, v := range r {
			if known[k] {
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// loadEdgeOutcomes decodes the -edge-outcomes JSON array into
// braintrain.EdgeOutcome records.
func loadEdgeOutcomes(path string) ([]braintrain.EdgeOutcome, error) {
	//nolint:gosec // G304: path is this CLI's own -edge-outcomes flag value,
	// an operator-supplied input file, never end-user/attacker input.
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read edge outcomes: %w", err)
	}
	var out []braintrain.EdgeOutcome
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode edge outcomes: %w", err)
	}
	return out, nil
}
