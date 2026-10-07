// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// setecSVIDSource is the SVID the daemon presents to the setec fleet and the
// trust bundle it checks the fleet with (ADR-0142). *workloadapi.X509Source
// satisfies it.
type setecSVIDSource interface {
	x509svid.Source
	x509bundle.Source
}

// errNoDaemonSVID reports a setec dial before the daemon has its SPIFFE
// Workload API source.
var errNoDaemonSVID = errors.New("setec dial: the daemon has no SPIFFE Workload API source")

// daemonSVIDSource reads the Workload API source of the daemon at each TLS
// handshake. The setec clients are built in New, before Start opens the
// source, and the first handshake happens after it.
type daemonSVIDSource struct {
	d *daemonImpl
}

func (s daemonSVIDSource) source() (setecSVIDSource, error) {
	src, ok := s.d.spiffeX509Source.(setecSVIDSource)
	if !ok || src == nil {
		return nil, errNoDaemonSVID
	}
	return src, nil
}

// GetX509SVID returns the SVID of the daemon.
func (s daemonSVIDSource) GetX509SVID() (*x509svid.SVID, error) {
	src, err := s.source()
	if err != nil {
		return nil, err
	}
	svid, err := src.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("setec dial: %w", err)
	}
	return svid, nil
}

// GetX509BundleForTrustDomain returns the trust bundle of td.
func (s daemonSVIDSource) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	src, err := s.source()
	if err != nil {
		return nil, err
	}
	b, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		return nil, fmt.Errorf("setec dial: %w", err)
	}
	return b, nil
}
