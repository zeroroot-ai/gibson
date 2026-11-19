// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentskill

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
)

func get(t *testing.T, p *Puller, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := (&http.Client{Transport: p.transport}).Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("send the request: %w", err)
	}
	return nil
}

// The tenant Puller refuses each address class after name resolution. The hosts
// are IP literals, so the dialer sees them as they are. No test connects: the
// guard refuses before connect(2).
func TestPuller_RefusesEachBlockedAddressClass(t *testing.T) {
	cases := []struct{ host, class string }{
		{"127.0.0.1", "loopback"},
		{"[::1]", "loopback"},
		{"10.1.2.3", "private"},
		{"172.16.0.9", "private"},
		{"192.168.1.1", "private"},
		{"[fd00::1]", "private"},
		{"169.254.169.254", "link-local"},
		{"[fe80::1]", "link-local"},
		{"100.64.0.1", "carrier-grade-nat"},
		{"239.255.255.250", "multicast"},
		{"[ff02::1]", "link-local"},
		{"0.0.0.0", "unspecified"},
		{"[::]", "unspecified"},
		{"[64:ff9b::a9fe:a9fe]", "nat64-embedded-link-local"},
	}
	p := NewPuller()
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			err := get(t, p, "https://"+tc.host+":9/v2/")
			if err == nil || !strings.Contains(err.Error(), "netguard: refusing to connect") ||
				!strings.Contains(err.Error(), tc.class) {
				t.Fatalf("error = %v, want a netguard refusal of class %q", err, tc.class)
			}
		})
	}
}

// HTTPS only: a plain http request is refused, with or without the address limit.
func TestPuller_RefusesHTTP(t *testing.T) {
	for name, p := range map[string]*Puller{
		"tenant":   NewPuller(),
		"operator": NewPuller(AllowPrivateAddresses()),
	} {
		t.Run(name, func(t *testing.T) {
			err := get(t, p, "http://registry.example/v2/")
			if err == nil || !strings.Contains(err.Error(), "HTTPS only") {
				t.Fatalf("error = %v, want an HTTPS only refusal", err)
			}
		})
	}
}

// The operator path allows a private address. This one has no listener, so the
// dial fails for another reason than the guard.
func TestPuller_OperatorPathAllowsAPrivateAddress(t *testing.T) {
	err := get(t, NewPuller(AllowPrivateAddresses()), "https://127.0.0.1:1/v2/")
	if err == nil || strings.Contains(err.Error(), "netguard") {
		t.Fatalf("error = %v, want a connection error and no guard refusal", err)
	}
}

// A reference whose host the registry client treats as plain http still fails.
func TestPuller_PullRefusesALocalReferenceOverHTTP(t *testing.T) {
	_, err := NewPuller().Pull(context.Background(),
		"127.0.0.1:5000/acme/x@sha256:"+strings.Repeat("a", 64), "x", authn.DefaultKeychain)
	if err == nil {
		t.Fatal("a pull of a loopback reference must fail")
	}
}

// The refusal of a registry address gives the hint of the Agent Skill pull. It
// does not name allow_private_llm_endpoints, which does not apply here.
func TestPuller_RefusalHintIsNotTheModelEndpointSetting(t *testing.T) {
	err := get(t, NewPuller(), "https://10.1.2.3:9/v2/")
	if err == nil {
		t.Fatal("want a refusal of a private address, got no error")
	}
	if strings.Contains(err.Error(), "allow_private_llm_endpoints") {
		t.Fatalf("error = %v, want no hint about allow_private_llm_endpoints", err)
	}
	if !strings.Contains(err.Error(), addressHint) {
		t.Fatalf("error = %v, want the hint %q", err, addressHint)
	}
}
