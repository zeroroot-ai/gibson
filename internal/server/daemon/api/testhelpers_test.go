// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var testSlogLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// blankServer returns a DaemonServer with no external dependencies wired.
// Only suitable for input-validation and nil-store branch tests.
//
// reembedTrigger is defaulted to the no-op (mirroring NewDaemonServer) so the
// field is never nil at request time — the provider-config handlers call
// s.reembedTrigger.Trigger unconditionally ([[0003]]: no request-path nil-guard).
//
// modelEndpointResolver resolves each host to a public address, so a save with
// a base_url does no DNS lookup. A test of the address check sets its own.
func blankServer() *DaemonServer {
	return &DaemonServer{
		logger:                testSlogLogger,
		reembedTrigger:        noopReembedTrigger{},
		modelEndpointResolver: publicResolver{},
	}
}

// publicResolver resolves each host to one public address.
type publicResolver struct{}

func (publicResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
}

func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	s, _ := status.FromError(err)
	return s.Code()
}
