// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// fakeDaemon answers the two trainer RPCs and records the stored artifacts.
type fakeDaemon struct {
	data     *daemonoperatorv1.GetBeliefTrainingDataResponse
	readErr  error
	storeErr error
	stored   []*daemonoperatorv1.StoreBeliefArtifactRequest
	closed   bool
}

func (f *fakeDaemon) GetBeliefTrainingData(
	_ context.Context, in *daemonoperatorv1.GetBeliefTrainingDataRequest, _ ...grpc.CallOption,
) (*daemonoperatorv1.GetBeliefTrainingDataResponse, error) {
	if in.GetTenantId() != "acme" {
		return nil, errors.New("wrong tenant")
	}
	return f.data, f.readErr
}

func (f *fakeDaemon) StoreBeliefArtifact(
	_ context.Context, in *daemonoperatorv1.StoreBeliefArtifactRequest, _ ...grpc.CallOption,
) (*daemonoperatorv1.StoreBeliefArtifactResponse, error) {
	if f.storeErr != nil {
		return nil, f.storeErr
	}
	f.stored = append(f.stored, in)
	return &daemonoperatorv1.StoreBeliefArtifactResponse{Version: int64(len(f.stored))}, nil
}

func (f *fakeDaemon) Close() error { f.closed = true; return nil }

func (f *fakeDaemon) dial(context.Context, string, string) (trainerClient, io.Closer, error) {
	return f, f, nil
}

func env(name string) string {
	return map[string]string{
		"GIBSON_DAEMON_GRPC_ADDRESS": "daemon:50051",
		"GIBSON_DAEMON_SPIFFE_ID":    "spiffe://example.org/platform/daemon",
	}[name]
}

func quietLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

// threeSettledBets is the training data of three hosts with a settled bet
// each: two exploits demonstrated and one refuted, and the edge outcomes that
// the settlements recorded.
func threeSettledBets() *daemonoperatorv1.GetBeliefTrainingDataResponse {
	row := func(vars map[string]bool) *daemonoperatorv1.BeliefTrainingRow {
		return &daemonoperatorv1.BeliefTrainingRow{Vars: vars}
	}
	return &daemonoperatorv1.GetBeliefTrainingDataResponse{
		Rows: []*daemonoperatorv1.BeliefTrainingRow{
			row(map[string]bool{"reachable": true, "svc_ssh": true, "exploit_demonstrated": true, "exploitable": true, "juicy": true}),
			row(map[string]bool{"reachable": true, "svc_https": true, "exploit_demonstrated": true, "exploitable": true, "juicy": false}),
			row(map[string]bool{"reachable": true, "svc_ssh": true, "exploitable": false, "juicy": false}),
		},
		EdgeOutcomes: []*daemonoperatorv1.EdgeOutcomeCount{
			{EdgeType: "RESOLVES_TO", Alpha: 2, Beta: 1},
		},
	}
}

// The acceptance test of gibson#614: the data of three settled bets gives
// both artifacts, and the runtime loaders parse the stored JSON back.
func TestRun_FitsAndStoresBothArtifacts(t *testing.T) {
	d := &fakeDaemon{data: threeSettledBets()}
	var logs bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"-tenant", "acme"}, env, d.dial, quietLogger(&logs)))

	require.Len(t, d.stored, 1)
	assert.True(t, d.closed, "the trainer releases its connection")
	req := d.stored[0]
	assert.Equal(t, "acme", req.GetTenantId())

	model, err := beliefvi.ParseModelArtifact(req.GetBeliefModel())
	require.NoError(t, err)
	assert.Equal(t, "tenant-acme-candidate", model.Version)
	_, err = beliefvi.NewBeliefModel(model)
	require.NoError(t, err, "the stored model loads into the runtime")
	base, err := beliefvi.DefaultArtifact()
	require.NoError(t, err)
	assert.NotEqual(t, base.CPDs["svc_ssh"].Values, model.CPDs["svc_ssh"].Values, "the rows moved the fit")

	edges, err := fit.ParseEdgePosteriorArtifact(req.GetEdgePosteriors())
	require.NoError(t, err)
	p := braintrain.EdgePosteriorProvider(edges).Posterior("RESOLVES_TO")
	assert.InDelta(t, 3.0, p.Alpha, 1e-9)
	assert.InDelta(t, 2.0, p.Beta, 1e-9)
	// gibson#720: the rows fit the in-node strengths and the leaks of a host.
	// Two of three reachable hosts are exploitable.
	s := braintrain.EdgePosteriorProvider(edges).InNodeStrength("Host", "exploitable", "reachable")
	assert.InDelta(t, 3.0, s.Alpha, 1e-9)
	assert.InDelta(t, 2.0, s.Beta, 1e-9)
	assert.Len(t, edges.Leaks, 3, "one leak for each Host variable")
	assert.Contains(t, logs.String(), "stored a new belief artifact version")
}

// A tenant with nothing to learn from gets no new version, and the run
// succeeds.
func TestRun_NoOutcomeStoresNothing(t *testing.T) {
	d := &fakeDaemon{data: &daemonoperatorv1.GetBeliefTrainingDataResponse{}}
	var logs bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"-tenant", "acme"}, env, d.dial, quietLogger(&logs)))
	assert.Empty(t, d.stored)
	assert.Contains(t, logs.String(), "no outcome to learn from")
}

// A failed read stops the run with an error.
func TestRun_ReadErrorFails(t *testing.T) {
	d := &fakeDaemon{readErr: errors.New("unavailable")}
	err := run(context.Background(), []string{"-tenant", "acme"}, env, d.dial, quietLogger(&bytes.Buffer{}))
	require.ErrorContains(t, err, "read the training data")
	assert.Empty(t, d.stored)
}

// A failed dial, a refused store and an outcome count that cannot fit each
// stop the run with an error.
func TestRun_FailuresStopTheRun(t *testing.T) {
	ctx := context.Background()
	args := []string{"-tenant", "acme"}
	logger := quietLogger(&bytes.Buffer{})

	noDial := func(context.Context, string, string) (trainerClient, io.Closer, error) {
		return nil, nil, errors.New("no SPIRE agent")
	}
	require.ErrorContains(t, run(ctx, args, env, noDial, logger), "no SPIRE agent")

	d := &fakeDaemon{data: threeSettledBets(), storeErr: errors.New("refused")}
	require.ErrorContains(t, run(ctx, args, env, d.dial, logger), "store the artifacts")

	bad := threeSettledBets()
	bad.EdgeOutcomes[0].Alpha = -1
	d = &fakeDaemon{data: bad}
	require.ErrorContains(t, run(ctx, args, env, d.dial, logger), "fit the artifacts")
	assert.Empty(t, d.stored)
}

// dialDaemon needs the SPIRE agent of the pod. Without its socket the dial
// fails with an error and leaks nothing.
func TestDialDaemon_NeedsTheSPIREAgent(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	_, _, err := dialDaemon(context.Background(), "daemon:50051", "spiffe://example.org/platform/daemon")
	require.ErrorContains(t, err, "connect to the daemon")
}

// The run refuses before it dials when a required input is missing.
func TestRun_RequiresTenantAndDaemon(t *testing.T) {
	d := &fakeDaemon{}
	noEnv := func(string) string { return "" }
	for name, tc := range map[string]struct {
		args   []string
		getenv func(string) string
	}{
		"no tenant":    {nil, env},
		"no address":   {[]string{"-tenant", "acme"}, noEnv},
		"no daemon id": {[]string{"-tenant", "acme", "-daemon-addr", "daemon:50051"}, noEnv},
		"bad flag":     {[]string{"-nope"}, env},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, run(context.Background(), tc.args, tc.getenv, d.dial, quietLogger(&bytes.Buffer{})))
		})
	}
	assert.False(t, d.closed, "no run dialed")
}

// The owner decision of gibson#614: the trainer talks only to the daemon. Its
// binary imports no Redis client and no Postgres driver. The standard library
// package database/sql is no driver: without one it cannot open a database.
// The ontology package that the trainer reads its belief schema from imports
// it.
func TestTrainerImportsNoDataStore(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	require.NoError(t, err)
	deps := strings.Fields(string(out))
	require.Contains(t, deps, "github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit", "the list is the deps of the trainer")
	for _, dep := range deps {
		for _, banned := range []string{"github.com/redis/", "github.com/jackc/", "github.com/lib/pq"} {
			assert.False(t, strings.HasPrefix(dep, banned), "the trainer imports %s", dep)
		}
	}
}

// writeBase writes a base model file: base-v1 with a new version name and one
// more service variable, so a test can tell the two apart.
func writeBase(t *testing.T, mutate func(*beliefvi.ModelArtifact)) string {
	t.Helper()
	art, err := beliefvi.DefaultArtifact()
	require.NoError(t, err)
	art.Version = "curated-test"
	art.Variables = append(art.Variables, "svc_ms-wbt-server")
	art.CPDs["svc_ms-wbt-server"] = beliefvi.CPDSpec{Values: [][]float64{{0.8}, {0.2}}}
	if mutate != nil {
		mutate(&art)
	}
	raw, err := json.Marshal(art)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "base.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// gibson#31: with a curated base model, the fit uses its structure.
func TestRun_FitsOnTheBaseModelFile(t *testing.T) {
	path := writeBase(t, nil)
	d := &fakeDaemon{data: threeSettledBets()}
	var logs bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"-tenant", "acme", "-base-model", path}, env, d.dial, quietLogger(&logs)))
	require.Len(t, d.stored, 1)
	model, err := beliefvi.ParseModelArtifact(d.stored[0].GetBeliefModel())
	require.NoError(t, err)
	assert.Contains(t, model.Variables, "svc_ms-wbt-server", "the fit keeps the variables of the base file")
}

// gibson#31: a new tenant with no outcome and no version starts on the
// curated base, not on base-v1.
func TestRun_ANewTenantGetsTheBaseModelAsItsFirstVersion(t *testing.T) {
	path := writeBase(t, nil)
	d := &fakeDaemon{data: &daemonoperatorv1.GetBeliefTrainingDataResponse{}}
	var logs bytes.Buffer
	getenv := func(name string) string {
		if name == BaseModelEnv {
			return path
		}
		return env(name)
	}
	require.NoError(t, run(context.Background(), []string{"-tenant", "acme"}, getenv, d.dial, quietLogger(&logs)))
	require.Len(t, d.stored, 1, "the base becomes the first version")
	model, err := beliefvi.ParseModelArtifact(d.stored[0].GetBeliefModel())
	require.NoError(t, err)
	base, err := beliefvi.ParseModelArtifact(mustRead(t, path))
	require.NoError(t, err)
	// No row moves the base. The fit keeps four decimal places.
	for state := range base.CPDs["exploitable"].Values {
		assert.InDeltaSlice(t, base.CPDs["exploitable"].Values[state], model.CPDs["exploitable"].Values[state], 1e-4)
	}
	assert.Contains(t, logs.String(), "the base model becomes its first version")
}

// A tenant that has a version and no new outcome gets nothing, even with a
// base file: the seed runs one time only.
func TestRun_ATenantWithAVersionIsNotSeededAgain(t *testing.T) {
	path := writeBase(t, nil)
	d := &fakeDaemon{data: &daemonoperatorv1.GetBeliefTrainingDataResponse{HasCurrentVersion: true}}
	var logs bytes.Buffer
	require.NoError(t, run(context.Background(), []string{"-tenant", "acme", "-base-model", path}, env, d.dial, quietLogger(&logs)))
	assert.Empty(t, d.stored)
}

// A base file that the runtime cannot query stops the run before any call.
func TestRun_RefusesABadBaseModel(t *testing.T) {
	missingQuery := writeBase(t, func(a *beliefvi.ModelArtifact) {
		// Drop juicy and the edges into it.
		var vars []string
		for _, v := range a.Variables {
			if v != "juicy" {
				vars = append(vars, v)
			}
		}
		a.Variables = vars
		delete(a.CPDs, "juicy")
		var edges [][2]string
		for _, e := range a.Edges {
			if e[1] != "juicy" {
				edges = append(edges, e)
			}
		}
		a.Edges = edges
	})
	notJSON := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(notJSON, []byte("not json"), 0o600))

	for name, path := range map[string]string{
		"no juicy":   missingQuery,
		"not a json": notJSON,
		"no file":    filepath.Join(t.TempDir(), "absent.json"),
	} {
		t.Run(name, func(t *testing.T) {
			d := &fakeDaemon{data: threeSettledBets()}
			var logs bytes.Buffer
			err := run(context.Background(), []string{"-tenant", "acme", "-base-model", path}, env, d.dial, quietLogger(&logs))
			require.Error(t, err)
			assert.Empty(t, d.stored)
		})
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // a path that the test names under t.TempDir()
	require.NoError(t, err)
	return raw
}
