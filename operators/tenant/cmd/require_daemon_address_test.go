// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRequireDaemonGRPCAddress_Missing(t *testing.T) {
	t.Parallel()
	addr, err := requireDaemonGRPCAddress(func(string) string { return "" })
	if !errors.Is(err, errNoDaemonGRPCAddress) {
		t.Fatalf("err = %v, want errNoDaemonGRPCAddress", err)
	}
	if addr != "" {
		t.Errorf("addr = %q, want empty", addr)
	}
	if !strings.Contains(err.Error(), "GIBSON_DAEMON_GRPC_ADDRESS") {
		t.Errorf("the error does not name the variable: %v", err)
	}
}

func TestRequireDaemonGRPCAddress_Present(t *testing.T) {
	t.Parallel()
	getenv := func(k string) string {
		if k == "GIBSON_DAEMON_GRPC_ADDRESS" {
			return "gibson:50051"
		}
		return ""
	}
	addr, err := requireDaemonGRPCAddress(getenv)
	if err != nil || addr != "gibson:50051" {
		t.Fatalf("addr = %q, err = %v, want the address and no error", addr, err)
	}
}

// TestMain_NoDaemonAddressNamesTheVariable reads main.go and proves that the
// start path calls requireDaemonGRPCAddress and exits on its error, and that
// no branch for an unset address is left. The start of the real binary needs
// a cluster, so the test reads the source.
func TestMain_NoDaemonAddressNamesTheVariable(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)
	call := "grpcAddr, addrErr := requireDaemonGRPCAddress(os.Getenv)"
	i := strings.Index(text, call)
	if i < 0 {
		t.Fatalf("main.go does not call %q", call)
	}
	after := text[i : i+len(call)+200]
	if !strings.Contains(after, "if addrErr != nil {") || !strings.Contains(after, "os.Exit(1)") {
		t.Errorf("main.go does not exit 1 on the error of requireDaemonGRPCAddress:\n%s", after)
	}
	if strings.Contains(text, `os.Getenv("GIBSON_DAEMON_GRPC_ADDRESS")`) {
		t.Error("main.go reads GIBSON_DAEMON_GRPC_ADDRESS directly, so a path with no address can exist")
	}
	if strings.Contains(text, "GIBSON_DAEMON_GRPC_ADDRESS unset") {
		t.Error("main.go still has the log line of the path with no daemon address")
	}
}
