// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package netguard_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/netguard"
)

func TestBlockedClass(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		// Blocked classes the SSRF guard must cover.
		{"127.0.0.1", "loopback"},
		{"127.53.1.9", "loopback"},
		{"::1", "loopback"},
		{"::ffff:127.0.0.1", "loopback"}, // IPv4-mapped IPv6 must normalise
		{"169.254.169.254", "link-local"},
		{"169.254.0.1", "link-local"},
		{"fe80::1", "link-local"},
		{"10.0.0.5", "private"},
		{"172.20.0.1", "private"},
		{"192.168.1.10", "private"},
		{"fd00::1", "private"}, // IPv6 unique-local
		{"fc00::1", "private"},
		{"100.64.0.1", "carrier-grade-nat"},
		{"100.127.255.254", "carrier-grade-nat"},
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"255.255.255.255", "broadcast"},
		{"224.0.0.1", "link-local"},      // 224.0.0.0/24 is link-local multicast
		{"239.255.255.250", "multicast"}, // SSDP
		{"192.0.0.1", "ietf-protocol-assignment"},
		{"198.18.0.1", "benchmarking"},
		{"240.0.0.1", "reserved"},
		{"64:ff9b::a9fe:a9fe", "nat64-embedded-link-local"}, // NAT64-wrapped IMDS

		// Public destinations must stay reachable.
		{"8.8.8.8", ""},
		{"1.1.1.1", ""},
		{"104.18.0.1", ""},
		{"2606:4700::1", ""},
		{"100.128.0.1", ""}, // just outside CGNAT
		{"172.32.0.1", ""},  // just outside RFC1918 172.16/12
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip, "test fixture %q must parse", tc.ip)
			assert.Equal(t, tc.want, netguard.BlockedClass(ip))
		})
	}
}

func TestBlockedClass_NilIsBlocked(t *testing.T) {
	assert.Equal(t, "unparseable", netguard.BlockedClass(nil))
}

func TestControl_RejectsBlockedAddresses(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:8080",
		"169.254.169.254:80",
		"10.0.0.5:11434",
		"100.64.1.1:443",
		"[fd00::1]:443",
		"[::1]:443",
		"0.0.0.0:80",
	} {
		t.Run(addr, func(t *testing.T) {
			err := netguard.Control("tcp", addr, nil)
			require.Error(t, err)
			var blocked *netguard.BlockedAddressError
			require.ErrorAs(t, err, &blocked, "want *BlockedAddressError, got %T", err)
			assert.Equal(t, addr, blocked.Addr)
		})
	}
}

func TestControl_AllowsPublicAddresses(t *testing.T) {
	assert.NoError(t, netguard.Control("tcp", "8.8.8.8:443", nil))
	assert.NoError(t, netguard.Control("tcp", "[2606:4700::1]:443", nil))
}

func TestControl_FailsClosedOnUnparseableAddress(t *testing.T) {
	require.Error(t, netguard.Control("tcp", "not-an-address", nil))
	// A hostname reaching Control means resolution happened outside our view.
	assert.Error(t, netguard.Control("tcp", "evil.example.com:80", nil))
}

// TestHTTPClient_RefusesBlockedAddressAtDialTime is the core regression test:
// the connection is refused before connect(2), so the server never sees a
// request and cannot act as a response oracle.
func TestHTTPClient_RefusesBlockedAddressAtDialTime(t *testing.T) {
	var hits atomic.Int32
	// httptest binds 127.0.0.1 — a blocked class, standing in for the in-cluster
	// service or 169.254.169.254 an attacker would target.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := netguard.HTTPClient(5*time.Second, false)
	resp, err := client.Get(srv.URL) //nolint:bodyclose // no response on the error path
	require.Error(t, err)
	require.Nil(t, resp)

	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked, "want *BlockedAddressError in chain, got %v", err)
	assert.Equal(t, "loopback", blocked.Class)
	assert.Zero(t, hits.Load(), "the blocked server must never be reached")
}

func TestHTTPClient_AllowPrivateBypassesTheGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := netguard.HTTPClient(5*time.Second, true)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestHTTPClient_RefusesRedirectToBlockedAddress proves the guard survives a
// redirect — the case a one-shot URL check cannot cover.
//
// A test process cannot bind a public IP, so the first hop (which stands in for
// a real, public LLM endpoint) is dialled directly; every subsequent dial — the
// redirect target — goes through the production guard untouched.
func TestHTTPClient_RefusesRedirectToBlockedAddress(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = w.Write([]byte("instance-credentials"))
	}))
	defer internal.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/latest/meta-data/", http.StatusFound)
	}))
	defer origin.Close()

	client := netguard.HTTPClient(5*time.Second, false)
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "netguard.HTTPClient must return an *http.Transport")

	guardedDial := tr.DialContext
	originAddr := origin.Listener.Addr().String()
	var firstHop atomic.Bool
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == originAddr && !firstHop.Swap(true) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		return guardedDial(ctx, network, addr)
	}

	resp, err := client.Get(origin.URL) //nolint:bodyclose // no response on the error path
	require.Error(t, err, "redirect to a loopback address must be refused")
	require.Nil(t, resp)

	var blocked *netguard.BlockedAddressError
	require.ErrorAs(t, err, &blocked, "want *BlockedAddressError in chain, got %v", err)
	assert.Equal(t, "loopback", blocked.Class)
	assert.Zero(t, internalHits.Load(), "the redirect target must never be reached")
}

// TestDialer_GuardIsInstalledUnlessAllowPrivate documents the one escape hatch.
func TestDialer_GuardIsInstalledUnlessAllowPrivate(t *testing.T) {
	assert.NotNil(t, netguard.Dialer(false).Control, "guard must be on by default")
	assert.Nil(t, netguard.Dialer(true).Control, "allowPrivate must remove the guard")
}

func TestDialContext_RefusesBlockedAddress(t *testing.T) {
	_, err := netguard.DialContext(context.Background(), "tcp", "169.254.169.254:80", false)
	require.Error(t, err)
	var blocked *netguard.BlockedAddressError
	assert.ErrorAs(t, err, &blocked)
}
