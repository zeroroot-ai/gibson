// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"errors"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type fakeSVIDSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
	err    error
}

func (f fakeSVIDSource) GetX509SVID() (*x509svid.SVID, error) { return f.svid, f.err }
func (f fakeSVIDSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return f.bundle, f.err
}
func (fakeSVIDSource) Close() error { return nil }

// The daemon SVID source reads the Workload API source at each call: none
// before Start, the SVID and the bundle after it, and each error named.
func TestDaemonSVIDSource_ReadsTheSourceAtEachCall(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	d := &daemonImpl{}
	s := daemonSVIDSource{d: d}
	if _, err := s.GetX509SVID(); !errors.Is(err, errNoDaemonSVID) {
		t.Fatalf("SVID before the source: %v", err)
	}
	if _, err := s.GetX509BundleForTrustDomain(td); !errors.Is(err, errNoDaemonSVID) {
		t.Fatalf("bundle before the source: %v", err)
	}

	want := &x509svid.SVID{ID: spiffeid.RequireFromPath(td, "/gibson")}
	bundle := x509bundle.New(td)
	d.spiffeX509Source = fakeSVIDSource{svid: want, bundle: bundle}
	if got, err := s.GetX509SVID(); err != nil || got != want {
		t.Fatalf("SVID = %v, %v; want the SVID of the source", got, err)
	}
	if got, err := s.GetX509BundleForTrustDomain(td); err != nil || got != bundle {
		t.Fatalf("bundle = %v, %v; want the bundle of the source", got, err)
	}

	down := errors.New("workload api down")
	d.spiffeX509Source = fakeSVIDSource{err: down}
	if _, err := s.GetX509SVID(); !errors.Is(err, down) {
		t.Fatalf("SVID error = %v; want the source error", err)
	}
	if _, err := s.GetX509BundleForTrustDomain(td); !errors.Is(err, down) {
		t.Fatalf("bundle error = %v; want the source error", err)
	}
}
