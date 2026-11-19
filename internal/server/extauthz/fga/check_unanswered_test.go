// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fga

import (
	"context"
	"errors"
	"testing"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// scriptedFGA answers each check with one fixed result.
type scriptedFGA struct {
	resp *fgaclient.ClientCheckResponse
	err  error
}

// scriptedReq embeds the request interface so that the methods of the OpenFGA
// SDK with a non-Go-style name come from the SDK, not from this test.
type scriptedReq struct {
	fgaclient.SdkClientCheckRequestInterface
	scriptedFGA
	body fgaclient.ClientCheckRequest
}

func (m *scriptedFGA) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &scriptedReq{scriptedFGA: *m}
}

func (r *scriptedReq) Body(b fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	r.body = b
	return r
}

func (r *scriptedReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}

func (r *scriptedReq) Execute() (*fgaclient.ClientCheckResponse, error) { return r.resp, r.err }

func (r *scriptedReq) GetContext() context.Context               { return context.Background() }
func (r *scriptedReq) GetBody() *fgaclient.ClientCheckRequest    { return &r.body }
func (r *scriptedReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

func TestCheckRelationAndMissionActive_FailClosedWhenFGAFailsOrIsSilent(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("fga down")
	tests := []struct {
		name    string
		fga     *scriptedFGA
		wantErr error
	}{
		{"the RPC fails", &scriptedFGA{err: rpcErr}, rpcErr},
		{"the answer has no Allowed field", &scriptedFGA{resp: &fgaclient.ClientCheckResponse{}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewChecker(tt.fga, &Registry{})
			calls := map[string]func() (bool, error){
				"CheckRelation": func() (bool, error) {
					return c.CheckRelation(ctx, "user:u", "can_use", "model:acme/m", nil)
				},
				"CheckMissionActive": func() (bool, error) { return c.CheckMissionActive(ctx, "acme", "m1") },
			}
			for name, call := range calls {
				allowed, err := call()
				if allowed {
					t.Errorf("%s allowed with no answer", name)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("%s error = %v, want %v", name, err, tt.wantErr)
				}
			}
		})
	}
}

func TestCheckRelationAndMissionActive_ReturnTheAnswer(t *testing.T) {
	ctx := context.Background()
	yes := true
	c := NewChecker(&scriptedFGA{resp: &fgaclient.ClientCheckResponse{
		CheckResponse: openfga.CheckResponse{Allowed: &yes},
	}}, &Registry{})
	if ok, err := c.CheckRelation(ctx, "user:u", "can_use", "model:acme/m", nil); err != nil || !ok {
		t.Fatalf("CheckRelation = %v, %v", ok, err)
	}
	if ok, err := c.CheckMissionActive(ctx, "acme", "m1"); err != nil || !ok {
		t.Fatalf("CheckMissionActive = %v, %v", ok, err)
	}
}
