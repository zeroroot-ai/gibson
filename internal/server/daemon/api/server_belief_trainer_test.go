// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
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
	e := brain.NewEngine(tenant)
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
	srv, _, worlds := trainerServer(t)
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
}

func TestStoreBeliefArtifact(t *testing.T) {
	srv, mock, _ := trainerServer(t)
	ctx := tlsPeerCtx(t, trainerOfAcme)
	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").
		WithArgs("acme", `{"v":1}`, `{"e":2}`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(3)))
	resp, err := srv.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: "acme", BeliefModel: []byte(`{"v":1}`), EdgePosteriors: []byte(`{"e":2}`),
	})
	if err != nil || resp.GetVersion() != 3 {
		t.Fatalf("store: %v %v, want version 3", resp, err)
	}

	for name, req := range map[string]*daemonoperatorv1.StoreBeliefArtifactRequest{
		"no model":         {TenantId: "acme", EdgePosteriors: []byte(`{}`)},
		"model not object": {TenantId: "acme", BeliefModel: []byte(`[1]`), EdgePosteriors: []byte(`{}`)},
	} {
		if _, err := srv.StoreBeliefArtifact(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code %v, want InvalidArgument", name, status.Code(err))
		}
	}

	mock.ExpectQuery("INSERT INTO tenant_belief_artifacts").WillReturnError(errors.New("db down"))
	if _, err := srv.StoreBeliefArtifact(ctx, &daemonoperatorv1.StoreBeliefArtifactRequest{
		TenantId: "acme", BeliefModel: []byte(`{}`), EdgePosteriors: []byte(`{}`),
	}); status.Code(err) != codes.Internal {
		t.Errorf("db error: code %v, want Internal", status.Code(err))
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
