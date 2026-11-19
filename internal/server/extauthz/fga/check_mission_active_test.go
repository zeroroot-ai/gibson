// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"sync"
	"testing"

	"github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// optionCapturingFGA records the request and the options of each check.
type optionCapturingFGA struct {
	allowed bool
	mu      sync.Mutex
	bodies  []fgaclient.ClientCheckRequest
	options []fgaclient.ClientCheckOptions
}

func (m *optionCapturingFGA) Check(context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &optionCapturingReq{m: m}
}

type optionCapturingReq struct {
	m    *optionCapturingFGA
	body fgaclient.ClientCheckRequest
	opts fgaclient.ClientCheckOptions
}

func (r *optionCapturingReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *optionCapturingReq) Options(o fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	r.opts = o
	return r
}

func (r *optionCapturingReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	r.m.mu.Lock()
	r.m.bodies = append(r.m.bodies, r.body)
	r.m.options = append(r.m.options, r.opts)
	r.m.mu.Unlock()
	v := r.m.allowed
	return &fgaclient.ClientCheckResponse{CheckResponse: openfga.CheckResponse{Allowed: &v}}, nil
}

func (r *optionCapturingReq) GetAuthorizationModelIdOverride() *string  { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *optionCapturingReq) GetStoreIdOverride() *string               { return nil } //nolint:revive,staticcheck // method name set by openfga SDK request interface
func (r *optionCapturingReq) GetContext() context.Context               { return context.Background() }
func (r *optionCapturingReq) GetBody() *fgaclient.ClientCheckRequest    { b := r.body; return &b }
func (r *optionCapturingReq) GetOptions() *fgaclient.ClientCheckOptions { o := r.opts; return &o }

// The mission gate check asks the exact question and asks for higher
// consistency, so a cache older than the confirmed write is not accepted.
func TestCheckMissionActive_AsksForHigherConsistency(t *testing.T) {
	mock := &optionCapturingFGA{allowed: true}
	c := NewCachedChecker(NewChecker(mock, &Registry{}), 0, 0)

	ok, err := c.CheckMissionActive(context.Background(), "acme", "m1")
	if err != nil || !ok {
		t.Fatalf("CheckMissionActive = %v, %v, want true and no error", ok, err)
	}
	if len(mock.bodies) != 1 {
		t.Fatalf("FGA asked %d questions, want 1", len(mock.bodies))
	}
	if b := mock.bodies[0]; b.User != "tenant:acme" || b.Relation != "active" || b.Object != "mission:m1" {
		t.Errorf("question = %+v", b)
	}
	pref := mock.options[0].Consistency
	if pref == nil || *pref != openfga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY {
		t.Errorf("consistency = %v, want HIGHER_CONSISTENCY", pref)
	}
}

// The plain check keeps the default consistency: only the mission gate pays for
// the higher one.
func TestCheckRelation_KeepsTheDefaultConsistency(t *testing.T) {
	mock := &optionCapturingFGA{allowed: true}
	c := NewChecker(mock, &Registry{})
	if _, err := c.CheckRelation(context.Background(), "u", "r", "o:1", nil); err != nil {
		t.Fatal(err)
	}
	if mock.options[0].Consistency != nil {
		t.Errorf("consistency = %v, want unset", *mock.options[0].Consistency)
	}
}

func TestCheckMissionActive_RefusesAnEmptyField(t *testing.T) {
	c := NewChecker(&optionCapturingFGA{allowed: true}, &Registry{})
	if ok, err := c.CheckMissionActive(context.Background(), "", "m1"); ok || err == nil {
		t.Errorf("CheckMissionActive with no tenant = %v, %v, want false and an error", ok, err)
	}
}
