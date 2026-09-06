// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"strings"
	"testing"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// installRegistrySpy records what the service asked to persist, and can fail on
// demand.
type installRegistrySpy struct {
	ComponentInstallRegistry

	got     *ComponentInstall
	failErr error
}

func (s *installRegistrySpy) Register(_ context.Context, install *ComponentInstall) error {
	s.got = install
	return s.failErr
}

// TestRegisterComponent_PersistFailureRejectsTheRegistration is the regression
// for gibson#1205.
//
// The durable install record failing was logged "non-fatal" and swallowed. That
// was true of the RPC and false of the platform: the live Redis registry
// recorded an instance the durable record never knew about, so the two stores
// diverged permanently and silently — for every component, since a nil
// descriptor set made the write impossible.
func TestRegisterComponent_PersistFailureRejectsTheRegistration(t *testing.T) {
	spy := &installRegistrySpy{failErr: errors.New("pq: null value in column violates not-null constraint")}
	svc := newParityServer()
	svc.WithComponentInstallRegistry(spy)

	_, err := svc.RegisterComponent(tenantCtx(), &componentpb.RegisterComponentRequest{
		Kind: "tool", Name: "zerocool-http", Version: "0.1.0",
	})
	if err == nil {
		t.Fatal("expected the registration to fail when its install record cannot be written")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("status = %s, want Internal", got)
	}
	if !strings.Contains(err.Error(), "zerocool-http") {
		t.Errorf("error = %v, want it to name the component", err)
	}
}

// TestDescriptorSetForDB_NilBindsAsEmptyNotNull guards the cause.
//
// proto_descriptor_set is NOT NULL DEFAULT ” — the schema's own statement that
// having none is legitimate. A component registered over ComponentService
// genuinely has none. The INSERT names the column, so the DEFAULT never applied
// and a nil []byte bound as NULL, failing the constraint on every registration.
func TestDescriptorSetForDB_NilBindsAsEmptyNotNull(t *testing.T) {
	got := descriptorSetForDB(nil)
	if got == nil {
		t.Fatal("nil descriptor set still binds as SQL NULL; it must bind as empty bytes")
	}
	if len(got) != 0 {
		t.Errorf("descriptor set = %v, want empty", got)
	}
}

func TestDescriptorSetForDB_KeepsARealDescriptorSet(t *testing.T) {
	// A compiled tool that DOES carry one must be stored verbatim.
	in := []byte{0x0a, 0x0b, 0x0c}
	got := descriptorSetForDB(in)
	if string(got) != string(in) {
		t.Errorf("descriptor set = %v, want it unchanged", got)
	}
}

// TestRegisterComponent_PersistsWhatTheCallerRegistered keeps the service's own
// hand-off honest: whatever the component said it is must reach the durable
// record, since that record is what the platform later accounts for.
func TestRegisterComponent_PersistsWhatTheCallerRegistered(t *testing.T) {
	spy := &installRegistrySpy{}
	svc := newParityServer()
	svc.WithComponentInstallRegistry(spy)

	if _, err := svc.RegisterComponent(tenantCtx(), &componentpb.RegisterComponentRequest{
		Kind: "tool", Name: "zerocool-http", Version: "0.1.0",
	}); err != nil {
		t.Fatalf("RegisterComponent: %v", err)
	}
	if spy.got == nil {
		t.Fatal("the service never asked to persist an install record")
	}
	if spy.got.Kind != "tool" || spy.got.Name != "zerocool-http" || spy.got.Version != "0.1.0" {
		t.Errorf("persisted %+v, want the registered kind/name/version", spy.got)
	}
}
