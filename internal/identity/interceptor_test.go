package identity

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// startTestServer boots an in-process gRPC server with both interceptors and
// returns a connected client plus a cleanup func.
func startTestServer(t *testing.T, secret []byte) (grpc_testing.TestServiceClient, func()) {
	t.Helper()
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(UnaryInterceptor(secret)),
		grpc.ChainStreamInterceptor(StreamInterceptor(secret)),
	)
	grpc_testing.RegisterTestServiceServer(srv, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(lis) //nolint:errcheck

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		srv.Stop()
		t.Fatalf("dial: %v", err)
	}
	return grpc_testing.NewTestServiceClient(conn), func() {
		conn.Close()
		srv.Stop()
	}
}

// signedMD builds outgoing metadata.MD with lowercase keys (required by gRPC),
// using the same sign helper as the headers tests so the end-to-end flow is exercised.
func signedMD(secret []byte, id Identity) metadata.MD {
	h := sign(secret, id)
	md := metadata.MD{}
	for k, vs := range h {
		// http.Header keys are title-cased; gRPC metadata requires lowercase.
		md[strings.ToLower(k)] = vs
	}
	return md
}

// echoServer implements grpc_testing.TestServiceServer minimally.
type echoServer struct {
	grpc_testing.UnimplementedTestServiceServer
}

func (e *echoServer) UnaryCall(ctx context.Context, req *grpc_testing.SimpleRequest) (*grpc_testing.SimpleResponse, error) {
	_, err := IdentityFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "identity missing in handler: %v", err)
	}
	return &grpc_testing.SimpleResponse{}, nil
}

func TestUnaryInterceptor_HappyPath(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	md := signedMD(testSecret, testID)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	_, err := client.UnaryCall(ctx, &grpc_testing.SimpleRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnaryInterceptor_HMACFailReturnsInternal(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	// Sign with the wrong secret.
	md := signedMD([]byte("wrong-secret"), testID)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	_, err := client.UnaryCall(ctx, &grpc_testing.SimpleRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v", status.Code(err))
	}
}

func TestUnaryInterceptor_MissingHeadersFail(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	// Empty metadata — all headers missing.
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{})
	_, err := client.UnaryCall(ctx, &grpc_testing.SimpleRequest{})
	if err == nil {
		t.Fatal("expected error for missing headers")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v", status.Code(err))
	}
}

func TestUnaryInterceptor_IdentityInContext(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	id := Identity{
		Subject:        "user:ctx-check",
		Issuer:         "spire",
		CredentialType: "mtls",
		Tenant:         "",
		IssuedAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
	md := signedMD(testSecret, id)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	// If IdentityFromContext fails inside echoServer, it returns codes.Internal.
	_, err := client.UnaryCall(ctx, &grpc_testing.SimpleRequest{})
	if err != nil {
		t.Fatalf("identity should be present in handler context: %v", err)
	}
}

func TestStreamInterceptor_HappyPath(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	md := signedMD(testSecret, testID)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	stream, err := client.FullDuplexCall(ctx)
	if err != nil {
		t.Fatalf("stream open error: %v", err)
	}
	// Close send side and receive EOF — enough to confirm the interceptor passed.
	stream.CloseSend() //nolint:errcheck
	_, recvErr := stream.Recv()
	// EOF or nil are both fine; Internal would indicate the interceptor rejected.
	if recvErr != nil && status.Code(recvErr) == codes.Internal {
		t.Fatalf("stream interceptor returned Internal: %v", recvErr)
	}
}

func TestStreamInterceptor_HMACFail(t *testing.T) {
	client, cleanup := startTestServer(t, testSecret)
	defer cleanup()

	md := signedMD([]byte("bad-secret"), testID)
	ctx := metadata.NewOutgoingContext(t.Context(), md)
	stream, err := client.FullDuplexCall(ctx)
	if err == nil {
		// Some servers reject at the interceptor before returning the stream object.
		stream.CloseSend() //nolint:errcheck
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("expected error from stream interceptor with bad secret")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v", status.Code(err))
	}
}
