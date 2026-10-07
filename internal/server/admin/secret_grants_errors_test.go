// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// failingSecrets is a SecretNameLister that refuses each list.
type failingSecrets struct{ err error }

func (f failingSecrets) List(context.Context, auth.TenantID) ([]string, error) { return nil, f.err }

func secretGrantServerWith(t *testing.T, az authz.Authorizer, names SecretNameLister) *GrantsAdminServer {
	t.Helper()
	srv, err := NewGrantsAdminServer(GrantsAdminConfig{Reader: noopReader{}, Authorizer: az, Lookup: secretGrantLookup(), SecretNames: names})
	if err != nil {
		t.Fatalf("NewGrantsAdminServer: %v", err)
	}
	return srv
}

// Each failure on the way to a grant write has its own code: no tenant, a
// secret list that cannot be read, grants that cannot be checked, and
// grants that cannot be written.
func TestWriteSecretGrants_Failures(t *testing.T) {
	req := &tenantv1.WriteSecretGrantsRequest{TargetPrincipalId: grantPlugin, SecretNames: []string{"cred:github_token"}}

	srv := newSecretGrantServer(t, &stubAuthorizer{present: map[string]bool{}})
	_, err := srv.WriteSecretGrants(context.Background(), req)
	wantCode(t, err, codes.PermissionDenied)

	unavailable := status.Error(codes.Unavailable, "secrets down")
	srv = secretGrantServerWith(t, &stubAuthorizer{present: map[string]bool{}}, failingSecrets{err: unavailable})
	_, err = srv.WriteSecretGrants(adminCtx(t, grantTenant), req)
	wantCode(t, err, codes.Unavailable)

	srv = secretGrantServerWith(t, &stubAuthorizer{present: map[string]bool{}}, failingSecrets{err: errors.New("broken")})
	_, err = srv.WriteSecretGrants(adminCtx(t, grantTenant), req)
	wantCode(t, err, codes.Internal)

	srv = newSecretGrantServer(t, &stubAuthorizer{present: map[string]bool{}, batchCheckErr: errors.New("fga down")})
	_, err = srv.WriteSecretGrants(adminCtx(t, grantTenant), req)
	wantCode(t, err, codes.Internal)

	srv = newSecretGrantServer(t, &stubAuthorizer{present: map[string]bool{}, writeErr: errors.New("fga down")})
	_, err = srv.WriteSecretGrants(adminCtx(t, grantTenant), req)
	wantCode(t, err, codes.Internal)
}
