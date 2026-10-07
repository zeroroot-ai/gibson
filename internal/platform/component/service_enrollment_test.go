// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// attestedCaller answers that every principal enrolled with an attested
// workload identity, the state of a catalog plugin on the platform.
type attestedCaller struct{}

func (attestedCaller) PrincipalIsAttested(context.Context, string, string) (bool, error) {
	return true, nil
}

// enrollmentAnswer is a reader with one fixed answer.
type enrollmentAnswer struct {
	attested bool
	err      error
}

func (e enrollmentAnswer) PrincipalIsAttested(context.Context, string, string) (bool, error) {
	return e.attested, e.err
}

// attestedRegistry keeps the ComponentInfo of the last Register call.
type attestedRegistry struct {
	noopRegistry
	got ComponentInfo
}

func (r *attestedRegistry) Register(_ context.Context, _, _, _ string, info ComponentInfo) (string, error) {
	r.got = info
	return "instance-1", nil
}

// TestRegisterComponent_RecordsPlacementFromTheEnrollmentRecord proves the
// daemon sets ComponentInfo.Attested from its own enrollment record, and
// refuses the check-in when it cannot read the record.
func TestRegisterComponent_RecordsPlacementFromTheEnrollmentRecord(t *testing.T) {
	ctx := credCallerCtx(t, "plugin_principal:github", "primary")
	for _, want := range []bool{true, false} {
		reg := &attestedRegistry{}
		svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
			WithEnrollmentReader(enrollmentAnswer{attested: want})
		if _, err := svc.RegisterComponent(ctx, minimalRegisterReq("tool", "my-tool")); err != nil {
			t.Fatalf("attested=%v: %v", want, err)
		}
		if reg.got.Attested != want {
			t.Fatalf("Attested = %v, want %v", reg.got.Attested, want)
		}
	}

	reg := &attestedRegistry{}
	svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil).
		WithEnrollmentReader(enrollmentAnswer{err: errors.New("db down")})
	_, err := svc.RegisterComponent(ctx, minimalRegisterReq("tool", "my-tool"))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a failed enrollment read: err = %v, want Unavailable", err)
	}
}

// TestRegisterComponent_CatalogPluginNameNeedsAnAttestedIdentity is the
// failing fixture for the rule that a catalog plugin name is not free
// (ADR-0066). A token-enrolled caller and a caller with no enrollment record
// are refused under the name "github". The attested workload checks in. A
// token-enrolled caller keeps every name the catalog does not list.
func TestRegisterComponent_CatalogPluginNameNeedsAnAttestedIdentity(t *testing.T) {
	ctx := credCallerCtx(t, "plugin_principal:310000000000000001", "primary")
	newSvc := func(r EnrollmentReader) (*ComponentServiceServer, *attestedRegistry) {
		reg := &attestedRegistry{}
		svc := NewComponentServiceServer(reg, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)
		if r != nil {
			svc.WithEnrollmentReader(r)
		}
		return svc, reg
	}

	for name, reader := range map[string]EnrollmentReader{
		"token enrollment": enrollmentAnswer{attested: false},
		"no reader":        nil,
	} {
		svc, reg := newSvc(reader)
		_, err := svc.RegisterComponent(ctx, minimalRegisterReq("plugin", "github"))
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: err = %v, want PermissionDenied", name, err)
		}
		if reg.got.Name != "" {
			t.Fatalf("%s: the refused check-in reached the registry", name)
		}
	}

	svc, reg := newSvc(enrollmentAnswer{attested: true})
	if _, err := svc.RegisterComponent(ctx, minimalRegisterReq("plugin", "github")); err != nil {
		t.Fatalf("the attested workload: %v", err)
	}
	if !reg.got.Attested {
		t.Fatal("the attested workload must be recorded as attested")
	}

	svc, _ = newSvc(enrollmentAnswer{attested: false})
	if _, err := svc.RegisterComponent(ctx, minimalRegisterReq("plugin", "my-own-plugin")); err != nil {
		t.Fatalf("a name the catalog does not list: %v", err)
	}
	if _, err := svc.RegisterComponent(ctx, minimalRegisterReq("agent", "claude")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a catalog agent name needs an attested identity too: err = %v", err)
	}
}
