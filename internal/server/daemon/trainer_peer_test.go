// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

var testTrainerTD = spiffeid.RequireTrustDomainFromString("install.example")

// A trainer identity may call the two trainer methods and nothing else. Any
// other identity is not decided here.
func TestTrainerBypassDecision(t *testing.T) {
	trainer := "spiffe://install.example/trainer/acme"
	for _, m := range []string{
		daemonoperatorv1.DaemonOperatorService_GetBeliefTrainingData_FullMethodName,
		daemonoperatorv1.DaemonOperatorService_StoreBeliefArtifact_FullMethodName,
	} {
		if ok, err := trainerBypassDecision(trainer, m, testTrainerTD); !ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want allowed", m, ok, err)
		}
	}
	ok, err := trainerBypassDecision(trainer,
		daemonoperatorv1.DaemonOperatorService_ListPendingTenantProvisioning_FullMethodName, testTrainerTD)
	if ok || status.Code(err) != codes.PermissionDenied {
		t.Errorf("another method: ok=%v err=%v, want PermissionDenied", ok, err)
	}
	for _, other := range []string{
		"spiffe://install.example/platform/tenant-operator",
		"spiffe://other.example/trainer/acme",
	} {
		if ok, err := trainerBypassDecision(other,
			daemonoperatorv1.DaemonOperatorService_GetBeliefTrainingData_FullMethodName, testTrainerTD); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want not decided here", other, ok, err)
		}
	}
	if ok, err := trainerBypassDecision(trainer,
		daemonoperatorv1.DaemonOperatorService_GetBeliefTrainingData_FullMethodName, spiffeid.TrustDomain{}); ok || err != nil {
		t.Errorf("no trust domain: ok=%v err=%v, want not decided", ok, err)
	}
}

// The TLS authorizer accepts the exact peers and the trainer identities of the
// trust domain, and refuses each other identity.
func TestAuthorizePeersOrTrainers(t *testing.T) {
	envoy := spiffeid.RequireFromString("spiffe://install.example/platform/envoy")
	exact := func(id spiffeid.ID, _ [][]*x509.Certificate) error {
		if id == envoy {
			return nil
		}
		return errors.New("not on the list")
	}
	authz := authorizePeersOrTrainers(exact, testTrainerTD)
	for _, ok := range []string{"spiffe://install.example/platform/envoy", "spiffe://install.example/trainer/acme"} {
		if err := authz(spiffeid.RequireFromString(ok), nil); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"spiffe://install.example/platform/rogue",
		"spiffe://other.example/trainer/acme",
		"spiffe://install.example/trainer/acme/x",
	} {
		if err := authz(spiffeid.RequireFromString(bad), nil); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := authorizePeersOrTrainers(exact, spiffeid.TrustDomain{})(
		spiffeid.RequireFromString("spiffe://install.example/trainer/acme"), nil); err == nil {
		t.Error("a trainer was accepted with no trust domain")
	}
}
