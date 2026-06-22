package fga

import (
	"context"
	"errors"
	"strings"
	"testing"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// stubClient is a FGAClient where Execute returns a configurable error.
type stubClient struct {
	err  error
	resp *fgaclient.ClientCheckResponse
}

func (s *stubClient) Check(_ context.Context) fgaclient.SdkClientCheckRequestInterface {
	return &stubReq{c: s}
}

type stubReq struct{ c *stubClient }

func (r *stubReq) Body(_ fgaclient.ClientCheckRequest) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *stubReq) Options(_ fgaclient.ClientCheckOptions) fgaclient.SdkClientCheckRequestInterface {
	return r
}
func (r *stubReq) Execute() (*fgaclient.ClientCheckResponse, error) {
	if r.c.err != nil {
		return nil, r.c.err
	}
	return r.c.resp, nil
}
func (r *stubReq) GetAuthorizationModelIdOverride() *string  { return nil }
func (r *stubReq) GetStoreIdOverride() *string               { return nil }
func (r *stubReq) GetContext() context.Context               { return context.Background() }
func (r *stubReq) GetBody() *fgaclient.ClientCheckRequest    { return nil }
func (r *stubReq) GetOptions() *fgaclient.ClientCheckOptions { return nil }

func TestSelfCheck_OK(t *testing.T) {
	f := false
	c := &stubClient{resp: &fgaclient.ClientCheckResponse{
		CheckResponse: openfga.CheckResponse{Allowed: &f},
	}}
	if err := SelfCheck(context.Background(), c, "openfga:8080"); err != nil {
		t.Fatalf("SelfCheck on healthy FGA returned error: %v", err)
	}
}

func TestSelfCheck_TransportError_PortMismatch(t *testing.T) {
	// This is the deploy#140 case: HTTP/1.x client → OpenFGA gRPC port.
	c := &stubClient{err: errors.New(
		`Post "http://openfga:8081/stores/.../check": net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x00\x00..."`,
	)}
	err := SelfCheck(context.Background(), c, "openfga:8081")
	if err == nil {
		t.Fatal("expected SelfCheck to fail on malformed HTTP response")
	}
	if !strings.Contains(err.Error(), "cannot reach OpenFGA") {
		t.Errorf("expected diagnostic prefix, got: %v", err)
	}
	if !strings.Contains(err.Error(), "openfga:8081") {
		t.Errorf("error should name the misconfigured addr, got: %v", err)
	}
	if !strings.Contains(err.Error(), "port/protocol mismatch") {
		t.Errorf("error should call out the port/protocol mismatch hint, got: %v", err)
	}
}

func TestSelfCheck_TransportError_DNS(t *testing.T) {
	c := &stubClient{err: errors.New(
		`Post "http://wrong-host:8080/stores/.../check": dial tcp: lookup wrong-host on 10.96.0.10:53: no such host`,
	)}
	err := SelfCheck(context.Background(), c, "wrong-host:8080")
	if err == nil {
		t.Fatal("expected SelfCheck to fail on DNS lookup error")
	}
	if !strings.Contains(err.Error(), "cannot reach OpenFGA") {
		t.Errorf("expected diagnostic prefix, got: %v", err)
	}
}

func TestSelfCheck_TransportError_ConnectionRefused(t *testing.T) {
	c := &stubClient{err: errors.New(
		`Post "http://openfga:8080/stores/.../check": dial tcp 10.0.0.1:8080: connect: connection refused`,
	)}
	err := SelfCheck(context.Background(), c, "openfga:8080")
	if err == nil {
		t.Fatal("expected SelfCheck to fail on connection refused")
	}
	if !strings.Contains(err.Error(), "cannot reach OpenFGA") {
		t.Errorf("expected diagnostic prefix, got: %v", err)
	}
}

func TestSelfCheck_NonTransportError_StoreNotFound(t *testing.T) {
	// Application-layer error from FGA (transport works, config wrong).
	// We still want SelfCheck to fail, but with the "Check round-trip
	// failed" prefix rather than the transport-class prefix.
	c := &stubClient{err: errors.New(
		`HTTP 404: store_id not found`,
	)}
	err := SelfCheck(context.Background(), c, "openfga:8080")
	if err == nil {
		t.Fatal("expected SelfCheck to surface application-layer errors")
	}
	if strings.Contains(err.Error(), "port/protocol mismatch") {
		t.Errorf("non-transport error should NOT be tagged as port/protocol mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "round-trip failed") {
		t.Errorf("expected 'round-trip failed' prefix on application error, got: %v", err)
	}
}

func TestSelfCheck_NilClient(t *testing.T) {
	err := SelfCheck(context.Background(), nil, "")
	if err == nil {
		t.Fatal("SelfCheck(nil) should return an error, not panic")
	}
}

func TestIsTransportError_Markers(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{`malformed HTTP response "\x00\x00..."`, true},
		{`no such host`, true},
		{`connect: connection refused`, true},
		{`tls: handshake failure`, true},
		{`x509: certificate signed by unknown authority`, true},
		{`store_id not found`, false},
		{`authorization_model not found`, false},
		{`HTTP 401: unauthorized`, false},
		{`HTTP 500: internal server error`, false},
	}
	for _, tc := range cases {
		if got := isTransportError(errors.New(tc.msg)); got != tc.want {
			t.Errorf("isTransportError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
	if isTransportError(nil) {
		t.Errorf("isTransportError(nil) should be false")
	}
}
