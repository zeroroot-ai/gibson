// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeFetcher returns a fixed customer or error.
type fakeFetcher struct {
	cust *StripeCustomer
	err  error
}

func (f *fakeFetcher) FetchStripeCustomer(context.Context, string) (*StripeCustomer, error) {
	return f.cust, f.err
}

func TestMetadataVerifier_OwnershipMatch_Allows(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{cust: &StripeCustomer{
		ID:       "cus_123",
		Metadata: map[string]string{"tenant_id": "acme", "tier": "team"},
	}}}
	if err := v.VerifyStripeCustomer(context.Background(), "cus_123", "acme"); err != nil {
		t.Fatalf("expected match to allow adoption, got %v", err)
	}
}

func TestMetadataVerifier_WrongTenant_Mismatch(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{cust: &StripeCustomer{
		ID:       "cus_123",
		Metadata: map[string]string{"tenant_id": "someone-else"},
	}}}
	err := v.VerifyStripeCustomer(context.Background(), "cus_123", "acme")
	if !errors.Is(err, ErrStripeCustomerMismatch) {
		t.Fatalf("expected ErrStripeCustomerMismatch, got %v", err)
	}
}

// A customer without the tenant_id linkage tag was not created by the
// platform's signup path at all — it must be a mismatch, not a pass.
func TestMetadataVerifier_NoLinkageMetadata_Mismatch(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{cust: &StripeCustomer{
		ID: "cus_foreign",
	}}}
	err := v.VerifyStripeCustomer(context.Background(), "cus_foreign", "acme")
	if !errors.Is(err, ErrStripeCustomerMismatch) {
		t.Fatalf("expected ErrStripeCustomerMismatch for missing tenant_id metadata, got %v", err)
	}
}

func TestMetadataVerifier_DeletedCustomer_Mismatch(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{cust: &StripeCustomer{
		ID:       "cus_123",
		Deleted:  true,
		Metadata: map[string]string{"tenant_id": "acme"},
	}}}
	err := v.VerifyStripeCustomer(context.Background(), "cus_123", "acme")
	if !errors.Is(err, ErrStripeCustomerMismatch) {
		t.Fatalf("expected ErrStripeCustomerMismatch for deleted customer, got %v", err)
	}
}

func TestMetadataVerifier_MissingCustomer_Mismatch(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{err: ErrStripeCustomerNotFound}}
	err := v.VerifyStripeCustomer(context.Background(), "cus_gone", "acme")
	if !errors.Is(err, ErrStripeCustomerMismatch) {
		t.Fatalf("expected ErrStripeCustomerMismatch for missing customer, got %v", err)
	}
}

// A transient fetch failure (Stripe unreachable) is NOT a mismatch — the
// caller retries next drain instead of permanently refusing adoption.
func TestMetadataVerifier_TransientFetchError_NotMismatch(t *testing.T) {
	v := &MetadataStripeCustomerVerifier{Fetcher: &fakeFetcher{err: errors.New("connection refused")}}
	err := v.VerifyStripeCustomer(context.Background(), "cus_123", "acme")
	if err == nil {
		t.Fatalf("expected error")
	}
	if errors.Is(err, ErrStripeCustomerMismatch) {
		t.Fatalf("transient fetch error must not be classified as mismatch: %v", err)
	}
}

func TestNoopVerifier_AlwaysAllows(t *testing.T) {
	if err := (NoopStripeCustomerVerifier{}).VerifyStripeCustomer(context.Background(), "cus_anything", "acme"); err != nil {
		t.Fatalf("no-op verifier must never refuse: %v", err)
	}
}

func TestHTTPFetcher_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/customers/cus_123" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk_test_x" {
			t.Errorf("authorization: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cus_123","object":"customer","metadata":{"tenant_id":"acme","tier":"team"}}`))
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	cust, err := f.FetchStripeCustomer(context.Background(), "cus_123")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if cust.ID != "cus_123" || cust.Metadata["tenant_id"] != "acme" {
		t.Errorf("customer: %+v", cust)
	}
}

func TestHTTPFetcher_404_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"resource_missing"}}`))
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_gone")
	if !errors.Is(err, ErrStripeCustomerNotFound) {
		t.Fatalf("expected ErrStripeCustomerNotFound, got %v", err)
	}
}

func TestHTTPFetcher_Non200_TransientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_123")
	if err == nil {
		t.Fatalf("expected error on 500")
	}
	if errors.Is(err, ErrStripeCustomerNotFound) {
		t.Fatalf("500 must not classify as not-found: %v", err)
	}
}

// TestHTTPFetcher_NonOK_LargeBody ensures the truncate path (body > 256 bytes)
// is exercised: the error must still be returned and must not classify as
// not-found.
//
//nolint:dupl // near-identical structure to TestHTTPFetcher_Non200_TransientError but exercises the large-body truncate path
func TestHTTPFetcher_Non200_LargeBodyTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// Write more than 256 bytes so the truncate(body, 256) branch fires.
		_, _ = w.Write(make([]byte, 512))
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_123")
	if err == nil {
		t.Fatalf("expected error on 400")
	}
	if errors.Is(err, ErrStripeCustomerNotFound) {
		t.Fatalf("400 must not classify as not-found: %v", err)
	}
}

// TestHTTPFetcher_NilClient uses the default (*http.Client) path by not
// setting Client, verifying the nil-guard initialises a real client instead
// of panicking. The httptest server proves the request actually completes.
func TestHTTPFetcher_NilClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cus_nilclient","metadata":{"tenant_id":"t1"}}`))
	}))
	defer srv.Close()

	// Client field intentionally left nil — the nil-guard must initialise one.
	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	cust, err := f.FetchStripeCustomer(context.Background(), "cus_nilclient")
	if err != nil {
		t.Fatalf("nil client path: %v", err)
	}
	if cust.ID != "cus_nilclient" {
		t.Errorf("id: got %q", cust.ID)
	}
}

// TestHTTPFetcher_InvalidJSONResponse covers the json.Unmarshal error path:
// a 200 response with non-JSON body must return an error, not a nil customer.
func TestHTTPFetcher_InvalidJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_badjson")
	if err == nil {
		t.Fatalf("expected error on invalid JSON response")
	}
}

// TestHTTPFetcher_DefaultBaseURL verifies that an empty BaseURL does not
// panic and falls back to the live Stripe origin constant. We cannot contact
// real Stripe in tests, so we just check the error is the right shape
// (connection refused / DNS failure — NOT ErrStripeCustomerNotFound, which
// would indicate a wrong status parse).
func TestHTTPFetcher_DefaultBaseURL(t *testing.T) {
	// Force an immediately-cancelled context so the real outbound HTTP dial
	// fails fast without network I/O — we only care that the code path
	// reaches hc.Do without panicking.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x"} // BaseURL empty → defaultStripeAPIBaseURL
	_, err := f.FetchStripeCustomer(ctx, "cus_defaultbase")
	// A cancelled-context dial error is expected.  The test fails only if the
	// code panics or returns ErrStripeCustomerNotFound (which would be wrong).
	if err == nil {
		t.Fatalf("expected error with cancelled context")
	}
	if errors.Is(err, ErrStripeCustomerNotFound) {
		t.Errorf("context-cancel dial error must not classify as not-found: %v", err)
	}
}

// TestHTTPFetcher_DoError covers the hc.Do error path: a client that always
// returns an error must surface the error without classifying it as not-found.
func TestHTTPFetcher_DoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hijack the connection to force hc.Do to return an error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close() // close mid-request → hc.Do gets EOF
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: srv.URL}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_doerr")
	if err == nil {
		t.Fatalf("expected error when connection closed mid-request")
	}
	if errors.Is(err, ErrStripeCustomerNotFound) {
		t.Errorf("Do error must not classify as not-found: %v", err)
	}
}

// TestHTTPFetcher_InvalidURL covers the http.NewRequestWithContext error path:
// a BaseURL containing an invalid control character causes request construction
// to fail before any network I/O occurs (gibson#1099).
func TestHTTPFetcher_InvalidURL(t *testing.T) {
	// A null byte in the URL causes url.Parse → http.NewRequestWithContext to
	// return a "invalid control character in URL" error.
	f := &HTTPStripeCustomerFetcher{APIKey: "sk_test_x", BaseURL: "http://stripe.example\x00"}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_123")
	if err == nil {
		t.Fatalf("expected error on invalid URL")
	}
}

// errorBodyReader always returns an error from Read, simulating a broken
// response body (e.g. a connection dropped mid-response).
type errorBodyReader struct{}

func (errorBodyReader) Read(_ []byte) (int, error) {
	return 0, errors.New("forced read error")
}

// errorBodyTransport is an http.RoundTripper that returns a 200 response
// whose body always errors on Read, so io.ReadAll returns an error
// (gibson#1099 coverage for the read-stripe-customer-response error path).
type errorBodyTransport struct{}

func (errorBodyTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errorBodyReader{}),
	}, nil
}

// TestHTTPFetcher_ReadBodyError covers the io.ReadAll error path: a response
// whose body always errors must surface the error without panicking.
func TestHTTPFetcher_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Serve a valid response so the httptest server address resolves.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := &HTTPStripeCustomerFetcher{
		APIKey:  "sk_test_x",
		BaseURL: srv.URL,
		Client:  &http.Client{Transport: errorBodyTransport{}},
	}
	_, err := f.FetchStripeCustomer(context.Background(), "cus_readfail")
	if err == nil {
		t.Fatalf("expected error when response body read fails")
	}
}

// TestTruncate exercises both branches of the truncate helper directly.
func TestTruncate(t *testing.T) {
	t.Run("short body returned as-is", func(t *testing.T) {
		got := truncate([]byte("hello"), 10)
		if got != "hello" {
			t.Errorf("got %q, want %q", got, "hello")
		}
	})
	t.Run("long body is cut at n", func(t *testing.T) {
		input := []byte("abcdefghij") // 10 bytes
		got := truncate(input, 5)
		want := "abcde…" // prefix + UTF-8 ellipsis
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
