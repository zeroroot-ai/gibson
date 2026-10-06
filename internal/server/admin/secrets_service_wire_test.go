// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package admin

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	secretsv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/secrets/v1"
)

// TestSecretsService_IsServedOnTheSDKPackage proves the cutover of gibson#531:
// a client that the sdk generates for gibson.secrets.v1.SecretsService reaches
// a handler of this package. Before the cutover the daemon registered only
// gibson.tenant.v1.SecretsService, so the same call returned Unimplemented.
//
// The server here is the stub that the daemon registers when the secrets stack
// is not ready. Its answer is Unavailable, which only a registered handler
// can give.
func TestSecretsService_IsServedOnTheSDKPackage(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	secretsv1.RegisterSecretsServiceServer(srv, NewUnavailableSecretsServer())
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("secrets test server exited: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})

	if _, ok := srv.GetServiceInfo()["gibson.secrets.v1.SecretsService"]; !ok {
		t.Fatalf("the server does not register gibson.secrets.v1.SecretsService: %v", srv.GetServiceInfo())
	}

	_, err = secretsv1.NewSecretsServiceClient(conn).ListSecrets(context.Background(), &secretsv1.ListSecretsRequest{})
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("ListSecrets through the sdk client returned %v (%v), want Unavailable from the registered handler", got, err)
	}
}
