// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import "errors"

// envDaemonGRPCAddress names the address of the daemon gRPC listener.
const envDaemonGRPCAddress = "GIBSON_DAEMON_GRPC_ADDRESS"

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
