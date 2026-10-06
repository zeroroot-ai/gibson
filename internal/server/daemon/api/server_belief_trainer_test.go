// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

var trainerTD = spiffeid.RequireTrustDomainFromString("install.example")

func tlsPeerCtx(t *testing.T, svid string) context.Context {
	t.Helper()
	cert := &x509.Certificate{}
	if svid != "" {
		u, err := url.Parse(svid)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{u}
	}
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
}

// fakeWorlds gives one live engine for each tenant, built on first use.
type fakeWorlds struct{ engines map[string]*brain.Engine }

func (f *fakeWorlds) For(tenant string) *brain.Engine {
	if f.engines == nil {
		f.engines = map[string]*brain.Engine{}
	}
	if e, ok := f.engines[tenant]; ok {
		return e
	}
	e := brain.NewEngine(tenant, braintest.NewMemTimelineStore())
	f.engines[tenant] = e
	return e
}

func trainerServer(t *testing.T) (*DaemonServer, sqlmock.Sqlmock, *fakeWorlds) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db
	worlds := &fakeWorlds{}
	srv.WithBeliefTrainer(worlds, trainerTD)
	return srv, mock, worlds
}

const (
	trainerOfAcme  = "spiffe://install.example/trainer/acme"
	trainerOfOther = "spiffe://install.example/trainer/globex"
)

// A trainer of tenant A gets PermissionDenied for tenant B on both RPCs. So
// does a call through the edge, another identity, an identity of another
// trust domain, and a call with no TLS peer.
func TestBeliefTrainerRPCs_OnlyTheTrainerOfTheTenant(t *testing.T) {
	srv, _, _ := trainerServer(t)
	refused := map[string]context.Context{
		"the trainer of another tenant": tlsPeerCtx(t, trainerOfOther),
		"through the edge":              tlsPeerCtx(t, "spiffe://install.example/platform/envoy"),
		"the tenant operator":           tlsPeerCtx(t, "spiffe://install.example/platform/tenant-operator"),
		"a trainer of another domain":   tlsPeerCtx(t, "spiffe://other.example/trainer/acme"),
		"a longer path":                 tlsPeerCtx(t, "spiffe://install.example/trainer/acme/x"),
		"no TLS peer":                   context.Background(),
	}
	for name, ctx := range refused {
		t.Run(name, func(t *testing.T) {
			_, err := srv.GetBeliefTrainingData(ctx, &daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("GetBeliefTrainingData: code %v, want PermissionDenied", status.Code(err))
			}
			_, err = srv.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
				TenantId: "acme", BeliefModel: []byte(`{}`), EdgePosteriors: []byte(`{}`),
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("StoreBeliefArtifact: code %v, want PermissionDenied", status.Code(err))
			}
		})
	}
}

// The trainer of the tenant reads the rows and the edge counts of the World.
func TestGetBeliefTrainingData_ReadsTheWorld(t *testing.T) {
	srv, mock, worlds := trainerServer(t)
	mock.ExpectQuery("SELECT belief_model, version").WithArgs("acme").WillReturnError(sql.ErrNoRows)
	e := worlds.For("acme")
	e.Submit(brain.EdgeOutcomeObserved{EdgeType: "ssh->root", Success: true})
	e.Submit(brain.EdgeOutcomeObserved{EdgeType: "ssh->root", Success: false})
	e.Submit(brain.EdgeOutcomeObserved{EdgeType: "a->b", Success: true})
	e.Tick()

	resp, err := srv.GetBeliefTrainingData(tlsPeerCtx(t, trainerOfAcme),
		&daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("GetBeliefTrainingData: %v", err)
	}
	got := resp.GetEdgeOutcomes()
	if len(got) != 2 || got[0].GetEdgeType() != "a->b" || got[1].GetEdgeType() != "ssh->root" {
		t.Fatalf("edge outcomes = %v, want two in edge type order", got)
	}
	if got[1].GetAlpha() != 1 || got[1].GetBeta() != 1 {
		t.Errorf("ssh->root = %v, want alpha 1 and beta 1", got[1])
	}
	if _, ok := worlds.engines["globex"]; ok {
		t.Error("the read touched the World of another tenant")
	}
	if resp.GetHasCurrentVersion() {
		t.Error("a tenant with no stored version reports one")
	}
}

// gibson#31: the response says whether the tenant has a current version, so
// a trainer with a curated base seeds only a tenant that has none. A read
// that fails is an error, never "no version".
func TestGetBeliefTrainingData_ReportsTheCurrentVersion(t *testing.T) {
	srv, mock, _ := trainerServer(t)
	mock.ExpectQuery("SELECT belief_model, version").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"belief_model", "version"}).AddRow(baseModelJSON(t), int64(3)))
	resp, err := srv.GetBeliefTrainingData(tlsPeerCtx(t, trainerOfAcme),
		&daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("GetBeliefTrainingData: %v", err)
	}
	if !resp.GetHasCurrentVersion() {
		t.Error("a tenant with a current version reports none")
	}

	mock.ExpectQuery("SELECT belief_model, version").WithArgs("acme").WillReturnError(errors.New("db down"))
	if _, err := srv.GetBeliefTrainingData(tlsPeerCtx(t, trainerOfAcme),
		&daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"}); status.Code(err) != codes.Internal {
		t.Errorf("a failed version read: code %v, want Internal", status.Code(err))
	}
}

// baseModelJSON is the embedded base model as a stored artifact.
func baseModelJSON(t *testing.T) []byte {
	t.Helper()
	art, err := beliefvi.DefaultArtifact()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// overconfidentModelJSON says that each host is exploitable. On a FALSE bet
// it scores worse than the base model.
func overconfidentModelJSON(t *testing.T) []byte {
	t.Helper()
	art, err := beliefvi.DefaultArtifact()
	if err != nil {
		t.Fatal(err)
	}
	spec := art.CPDs["exploitable"]
	cols := len(spec.Values[1])
	spec.Values = [][]float64{make([]float64, cols), make([]float64, cols)}
	for c := range cols {
		spec.Values[0][c], spec.Values[1][c] = 0.01, 0.99
	}
	art.CPDs["exploitable"] = spec
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const edgesJSON = `{"version":"tenant-acme-candidate","posteriors":{"RESOLVES_TO":{"alpha":2,"beta":1}}}`

// settleAFalseBet gives the World of acme one host and a bet on it that
// settled FALSE.
func settleAFalseBet(worlds *fakeWorlds) {
	e := worlds.For("acme")
	e.Submit(brain.HostObserved{ScopeID: "s1", Address: "10.0.0.1", OpenPorts: []int{22}})
	e.Submit(brain.HypothesisObserved{
		ScopeID: "s1", Claim: "exploitable", HypothesisID: "h1",
		References: []brain.ReferencedEntityRef{{Label: "Host", IDProperties: map[string]string{"address": "10.0.0.1"}}},
	})
	e.Submit(brain.BetSettledFalse{HypothesisID: "h1", ScopeID: "s1"})
	e.Tick()
}

// The first version of a tenant with no settled bet scores the same as the
// base model, so it becomes current.
func TestStoreBeliefArtifact_AcceptsAVersionThatIsNotWorse(t *testing.T) {
	srv, mock, _ := trainerServer(t)
	ctx := tlsPeerCtx(t, trainerOfAcme)
	model := baseModelJSON(t)
	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").
		WithArgs("acme", string(model), edgesJSON).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(3)))
	mock.ExpectQuery("SELECT belief_model, version").WithArgs("acme").WillReturnError(sql.ErrNoRows)
	mock.ExpectBegin()
	mock.ExpectExec("SET state = \\$2").WithArgs("acme", "retired", "current").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SET    state = \\$3").
		WithArgs("acme", int64(3), "current", 0.0, 0.0, 0, "candidate").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	resp, err := srv.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: "acme", BeliefModel: model, EdgePosteriors: []byte(edgesJSON),
	})
	if err != nil || resp.GetVersion() != 3 {
		t.Fatalf("store: %v %v, want version 3", resp, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// The acceptance test of gibson#789: a version that scores worse on the
// settled bets is stored and marked rejected, and the current version does
// not change: no statement retires it.
func TestStoreBeliefArtifact_RejectsAWorseVersion(t *testing.T) {
	srv, mock, worlds := trainerServer(t)
	settleAFalseBet(worlds)
	ctx := tlsPeerCtx(t, trainerOfAcme)
	worse := overconfidentModelJSON(t)

	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(4)))
	mock.ExpectQuery("SELECT belief_model, version").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"belief_model", "version"}).AddRow(string(baseModelJSON(t)), int64(2)))
	mock.ExpectBegin()
	mock.ExpectExec("SET    state = \\$3").
		WithArgs("acme", int64(4), "rejected", sqlmock.AnyArg(), sqlmock.AnyArg(), 1, "candidate").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	before := testutil.ToFloat64(beliefVersionsTotal.WithLabelValues("acme", "rejected"))
	resp, err := srv.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: "acme", BeliefModel: worse, EdgePosteriors: []byte(edgesJSON),
	})
	if err != nil || resp.GetVersion() != 4 {
		t.Fatalf("store: %v %v, want version 4", resp, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
	if got := testutil.ToFloat64(beliefVersionsTotal.WithLabelValues("acme", "rejected")) - before; got != 1 {
		t.Errorf("rejected versions counted %v, want 1", got)
	}
}

// The verdict compares the two scores of the settled bets.
func TestJudgeBeliefVersion(t *testing.T) {
	worlds := &fakeWorlds{}
	settleAFalseBet(worlds)
	var cases []brain.BetCase
	worlds.For("acme").ReadWorld(func(w *brain.World) { cases = w.SettledBetCases() })

	base, err := parseBeliefModel(baseModelJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	worse, err := parseBeliefModel(overconfidentModelJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	if v := judgeBeliefVersion(worse, base, cases); v.Accepted || v.ScoredBets != 1 || v.BrierCandidate <= v.BrierCurrent {
		t.Errorf("worse candidate: %+v, want rejected with a higher score", v)
	}
	if v := judgeBeliefVersion(base, worse, cases); !v.Accepted {
		t.Errorf("better candidate: %+v, want accepted", v)
	}
	if v := judgeBeliefVersion(base, base, cases); !v.Accepted {
		t.Errorf("equal candidate: %+v, want accepted", v)
	}
}

// Each request that the store cannot take gets a clear code, and nothing
// reaches the database before the artifacts parse.
func TestStoreBeliefArtifact_RefusesBadArtifacts(t *testing.T) {
	srv, mock, _ := trainerServer(t)
	ctx := tlsPeerCtx(t, trainerOfAcme)
	model := baseModelJSON(t)
	for name, req := range map[string]*daemonoperatorv1.StoreBeliefArtifactRequest{
		"no model":          {TenantId: "acme", EdgePosteriors: []byte(edgesJSON)},
		"model not object":  {TenantId: "acme", BeliefModel: []byte(`[1]`), EdgePosteriors: []byte(edgesJSON)},
		"model no query":    {TenantId: "acme", BeliefModel: []byte(`{"variables":[]}`), EdgePosteriors: []byte(edgesJSON)},
		"model not a model": {TenantId: "acme", BeliefModel: []byte(`{"variables":["juicy","exploitable","reachable"],"cpds":{}}`), EdgePosteriors: []byte(edgesJSON)},
		"edges no version":  {TenantId: "acme", BeliefModel: model, EdgePosteriors: []byte(`{"posteriors":{}}`)},
	} {
		if _, err := srv.StoreBeliefArtifact(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code %v, want InvalidArgument", name, status.Code(err))
		}
	}

	ok := &daemonoperatorv1.StoreBeliefArtifactRequest{TenantId: "acme", BeliefModel: model, EdgePosteriors: []byte(edgesJSON)}
	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").WillReturnError(errors.New("db down"))
	if _, err := srv.StoreBeliefArtifact(ctx, ok); status.Code(err) != codes.Internal {
		t.Errorf("insert error: code %v, want Internal", status.Code(err))
	}

	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(5)))
	mock.ExpectQuery("SELECT belief_model, version").WillReturnError(errors.New("db down"))
	if _, err := srv.StoreBeliefArtifact(ctx, ok); status.Code(err) != codes.Internal {
		t.Errorf("current read error: code %v, want Internal", status.Code(err))
	}

	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(6)))
	mock.ExpectQuery("SELECT belief_model, version").
		WillReturnRows(sqlmock.NewRows([]string{"belief_model", "version"}).AddRow(`{"variables":[]}`, int64(2)))
	if _, err := srv.StoreBeliefArtifact(ctx, ok); status.Code(err) != codes.Internal {
		t.Errorf("corrupt current version: code %v, want Internal", status.Code(err))
	}

	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(7)))
	mock.ExpectQuery("SELECT belief_model, version").WillReturnError(sql.ErrNoRows)
	mock.ExpectBegin().WillReturnError(errors.New("db down"))
	if _, err := srv.StoreBeliefArtifact(ctx, ok); status.Code(err) != codes.Internal {
		t.Errorf("verdict error: code %v, want Internal", status.Code(err))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestBeliefTrainerRPCs_Unwired(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.GetBeliefTrainingData(tlsPeerCtx(t, trainerOfAcme), &daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code %v, want Unavailable", status.Code(err))
	}
}

// Each request that the handlers cannot serve gets a clear code.
func TestBeliefTrainerRPCs_RefuseWhatTheyCannotServe(t *testing.T) {
	ctx := tlsPeerCtx(t, trainerOfAcme)
	store := &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: "acme", BeliefModel: []byte(`{}`), EdgePosteriors: []byte(`{}`),
	}

	srv, _, _ := trainerServer(t)
	if _, err := srv.GetBeliefTrainingData(ctx, &daemonoperatorv1.GetBeliefTrainingDataRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no tenant: code %v, want InvalidArgument", status.Code(err))
	}

	noBrain := newPendingServer().WithBeliefTrainer(nil, trainerTD)
	if _, err := noBrain.GetBeliefTrainingData(ctx, &daemonoperatorv1.GetBeliefTrainingDataRequest{TenantId: "acme"}); status.Code(err) != codes.Unavailable {
		t.Errorf("no brain: code %v, want Unavailable", status.Code(err))
	}
	if _, err := noBrain.StoreBeliefArtifact(ctx, store); status.Code(err) != codes.Unavailable {
		t.Errorf("no platform Postgres: code %v, want Unavailable", status.Code(err))
	}
}
