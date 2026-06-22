// Command belief-trainer is the offline batch trainer for the belief field
// (ADR-0006, gibson#753). It fits a NEW versioned PER-TENANT belief model from a
// tenant's outcomes + HITL labels and writes it in the exact artifact format the
// pgmpy sidecar loads (ADR-0005, gibson#750).
//
// It is strictly OUT-OF-BAND — never the daemon hot path, never online learning
// (that would break deterministic replay). In production the daemon drives the
// in-process library entrypoint braintrain.TrainTenant against the live per-tenant
// Registry on a schedule; this CLI is the standalone/self-hoster + CI-smoke path,
// fitting from a JSON training-rows file so it needs neither a daemon nor pgmpy.
//
// Usage:
//
//	belief-trainer -tenant acme -base sidecar/belief/models/base-v1.json \
//	    -rows rows.json -out sidecar/belief/models
//
// rows.json is a JSON array of {var:bool} objects (one per observed host), e.g.
//
//	[{"reachable":true,"svc_ssh":true,"exploitable":true,"juicy":true}, ...]
//
// The trained artifact is written to <out>/tenant-<tenant>-v<n>.json with n one
// past the highest existing per-tenant version (past versions are never reused,
// so a mission that pinned vN can always re-load it).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "belief-trainer:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		tenant = flag.String("tenant", "", "tenant id the model is trained for (required)")
		base   = flag.String("base", "", "path to the base model artifact (structural template; required)")
		rows   = flag.String("rows", "", "path to a JSON array of training rows {var:bool} (required)")
		out    = flag.String("out", ".", "output directory for the versioned per-tenant artifact")
	)
	flag.Parse()

	if *tenant == "" || *base == "" || *rows == "" {
		flag.Usage()
		return fmt.Errorf("-tenant, -base and -rows are required")
	}

	baseArtifact, err := braintrain.LoadArtifact(*base)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, v := range baseArtifact.Variables {
		known[v] = true
	}

	trainingRows, err := loadRows(*rows, known)
	if err != nil {
		return err
	}

	version := braintrain.NextVersion(*out, *tenant)
	trained, err := braintrain.Fit(baseArtifact, trainingRows, version)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	path := *out + "/" + version + ".json"
	if err := trained.Write(path); err != nil {
		return err
	}
	fmt.Printf("trained %s from %d rows -> %s\n", version, len(trainingRows), path)
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
