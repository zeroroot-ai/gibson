// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func grantHeaderCtx(values ...string) context.Context {
	md := metadata.MD{}
	for _, v := range values {
		md.Append("x-capability-grant", v)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

// callerTaskGrant refuses every grant that is not the daemon's own task grant
// of the tenant, and reads the mission and the run of one that is.
func TestCallerTaskGrant(t *testing.T) {
	svc := &ComponentServiceServer{}
	svc.WithGrantVerifier(fakeGrants{})

	mission, run, err := svc.callerTaskGrant(grantHeaderCtx("Bearer "+grantToken("JWT", "m-1", "r-1", "sig")), "test-tenant")
	if err != nil || mission != "m-1" || run != "r-1" {
		t.Fatalf("a task grant: mission=%q run=%q err=%v, want m-1 r-1", mission, run, err)
	}

	refused := map[string]struct {
		svc    *ComponentServiceServer
		ctx    context.Context
		tenant string
	}{
		"no metadata":                {svc, context.Background(), "test-tenant"},
		"a token with no parts":      {svc, grantHeaderCtx("not-a-token"), "test-tenant"},
		"a header that is no base64": {svc, grantHeaderCtx("%%%.b.c"), "test-tenant"},
		"a header that is no JSON":   {svc, grantHeaderCtx("bm9wZQ.b.c"), "test-tenant"},
		"another tenant":             {svc, grantHeaderCtx(grantToken("JWT", "m-1", "r-1", "sig")), "other-tenant"},
		"no verifier":                {&ComponentServiceServer{}, grantHeaderCtx(grantToken("JWT", "m-1", "r-1", "sig")), "test-tenant"},
	}
	for name, tc := range refused {
		_, _, err := tc.svc.callerTaskGrant(tc.ctx, tc.tenant)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: err = %v, want PermissionDenied", name, err)
		}
	}

	if got := grantPayloadClaim("%%%", "mrid"); got != "" {
		t.Errorf("a payload that is no base64: claim = %q, want empty", got)
	}
	if got := grantPayloadClaim("bm9wZQ", "mrid"); got != "" {
		t.Errorf("a payload that is no JSON: claim = %q, want empty", got)
	}
}
