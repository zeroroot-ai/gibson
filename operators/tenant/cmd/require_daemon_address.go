// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// envDaemonGRPCAddress names the address of the daemon gRPC listener.
const envDaemonGRPCAddress = "GIBSON_DAEMON_GRPC_ADDRESS"

// envDaemonSPIFFEID names the SPIFFE ID of the daemon. It holds the trust
// domain of the install, and no code holds that as a literal (ADR-0164).
const envDaemonSPIFFEID = "GIBSON_DAEMON_SPIFFE_ID"

// errNoDaemonGRPCAddress names the missing dependency. main() logs it and
// exits 1 ([[0003]]).
var errNoDaemonGRPCAddress = errors.New(
	envDaemonGRPCAddress + " is required: the tenant-operator reports tenant status to the daemon, " +
		"and it drains the provisioning queues of the daemon; set it to the daemon gRPC address")

// requireDaemonGRPCAddress returns the daemon gRPC address, or an error that
// names the variable when it is unset. The daemon is a required dependency of
// the operator ([[0002]]), so no code path runs without its client.
//
// The function takes a getenv functor so a test covers the contract without a
// change of the process environment.
func requireDaemonGRPCAddress(getenv func(string) string) (string, error) {
	addr := getenv(envDaemonGRPCAddress)
	if addr == "" {
		return "", errNoDaemonGRPCAddress
	}
	return addr, nil
}

// newDaemonClientFunc builds the daemon gRPC client. Production passes
// provision.NewEntitlementsGRPCClient.
type newDaemonClientFunc func(
	ctx context.Context, addr, daemonSVID string, tokens provision.TokenSource,
) (*provision.EntitlementsGRPCClient, error)

// daemonClientFromEnv builds the daemon gRPC client from the address and the
// SPIFFE ID of the daemon. Both are required: the client refuses an empty
// SPIFFE ID. It returns the address so the caller can log it.
func daemonClientFromEnv(
	ctx context.Context, getenv func(string) string, tokens provision.TokenSource, newClient newDaemonClientFunc,
) (*provision.EntitlementsGRPCClient, string, error) {
	addr, err := requireDaemonGRPCAddress(getenv)
	if err != nil {
		return nil, "", err
	}
	client, err := newClient(ctx, addr, getenv(envDaemonSPIFFEID), tokens)
	if err != nil {
		return nil, addr, fmt.Errorf("daemon gRPC client (%s): %w", envDaemonSPIFFEID, err)
	}
	return client, addr, nil
}
