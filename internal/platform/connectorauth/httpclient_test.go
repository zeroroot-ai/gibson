// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A vendor on the loopback interface stands in for every cluster-internal
// address a tenant admin could name. With the guard on, the daemon must not
// open a connection to it at all.
func TestDiscover_RefusesAPrivateVendorByDefault(t *testing.T) {
	var hits atomic.Int32
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer vendor.Close()

	// THE FIXTURE THIS EXISTS FOR: nil client means the fail-closed default.
	_, err := Discover(context.Background(), nil, vendor.URL, vendor.URL)
	if err == nil {
		t.Fatalf("Discover reached a loopback vendor with the default client")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("the vendor received %d request(s); the guard must refuse before connecting", got)
	}

	// The same call with the operator's opt-in reaches the vendor.
	_, _ = Discover(context.Background(), NewHTTPClient(5*time.Second, true), vendor.URL, vendor.URL)
	if hits.Load() == 0 {
		t.Fatalf("with allowPrivate the vendor must be reachable")
	}
}

func TestValidateEndpointURL(t *testing.T) {
	cases := []struct {
		raw          string
		allowPrivate bool
		ok           bool
	}{
		{"https://gitlab.example.com", false, true},
		{"http://gitlab.example.com", false, false},
		{"http://gitlab.internal", true, true},
		{"ftp://gitlab.example.com", true, false},
		{"file:///etc/passwd", true, false},
		{"https://user:pw@gitlab.example.com", false, false},
		{"https://", false, false},
		{"not a url", false, false},
	}
	for _, tc := range cases {
		err := ValidateEndpointURL(tc.raw, tc.allowPrivate)
		if (err == nil) != tc.ok {
			t.Errorf("%q allowPrivate=%v: err=%v want ok=%v", tc.raw, tc.allowPrivate, err, tc.ok)
		}
	}
}

// A vendor that answers a public https request with a redirect to a
// plaintext URL must be stopped at the redirect: the transport judges every
// hop, not only the first.
func TestGuardedTransport_RefusesARedirectOffHTTPS(t *testing.T) {
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme == "http" {
			t.Fatalf("the plaintext hop reached the inner transport: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://10.0.0.1/token"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	client := &http.Client{Transport: &guardedTransport{allowPrivate: false, inner: inner}}
	_, err := client.Get("https://vendor.example.com/.well-known/openid-configuration")
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("want the redirect refused for its scheme, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
