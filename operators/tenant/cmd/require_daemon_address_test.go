// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
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
// start path builds the daemon client through daemonClientFromEnv and exits
// on its error, and that no branch for an unset address is left. The start of
// the real binary needs a cluster, so the test reads the source.
func TestMain_NoDaemonAddressNamesTheVariable(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(src)
	call := "grpcClient, grpcAddr, gerr := daemonClientFromEnv("
	i := strings.Index(text, call)
	if i < 0 {
		t.Fatalf("main.go does not call %q", call)
	}
	after := text[i : i+len(call)+300]
	if !strings.Contains(after, "if gerr != nil {") || !strings.Contains(after, "os.Exit(1)") {
		t.Errorf("main.go does not exit 1 on the error of daemonClientFromEnv:\n%s", after)
	}
	for _, read := range []string{`os.Getenv("GIBSON_DAEMON_GRPC_ADDRESS")`, `os.Getenv("GIBSON_DAEMON_SPIFFE_ID")`} {
		if strings.Contains(text, read) {
			t.Errorf("main.go has %s, so a path that skips the check can exist", read)
		}
	}
	if strings.Contains(text, "GIBSON_DAEMON_GRPC_ADDRESS unset") {
		t.Error("main.go still has the log line of the path with no daemon address")
	}
}

// daemonEnv is a getenv with the daemon address and SPIFFE ID set.
func daemonEnv(k string) string {
	switch k {
	case envDaemonGRPCAddress:
		return "gibson:50051"
	case envDaemonSPIFFEID:
		return "spiffe://example.org/platform/daemon"
	}
	return ""
}

// The client is built from the address and the SPIFFE ID in the env. With no
// address no client is built, and a client error names the SPIFFE ID variable.
func TestDaemonClientFromEnv(t *testing.T) {
	t.Parallel()
	want := &provision.EntitlementsGRPCClient{}
	var gotAddr, gotSVID string
	ok := func(_ context.Context, addr, svid string, _ provision.TokenSource) (*provision.EntitlementsGRPCClient, error) {
		gotAddr, gotSVID = addr, svid
		return want, nil
	}
	client, addr, err := daemonClientFromEnv(context.Background(), daemonEnv, nil, ok)
	if err != nil || client != want || addr != "gibson:50051" {
		t.Fatalf("client=%p addr=%q err=%v", client, addr, err)
	}
	if gotAddr != "gibson:50051" || gotSVID != "spiffe://example.org/platform/daemon" {
		t.Errorf("the client was built with addr=%q svid=%q", gotAddr, gotSVID)
	}

	called := false
	never := func(context.Context, string, string, provision.TokenSource) (*provision.EntitlementsGRPCClient, error) {
		called = true
		return nil, nil
	}
	if _, _, err := daemonClientFromEnv(context.Background(), func(string) string { return "" }, nil, never); !errors.Is(err, errNoDaemonGRPCAddress) {
		t.Errorf("no address: err = %v, want errNoDaemonGRPCAddress", err)
	}
	if called {
		t.Error("a client was built with no address")
	}

	refuse := func(context.Context, string, string, provision.TokenSource) (*provision.EntitlementsGRPCClient, error) {
		return nil, errors.New("DaemonSVID is required")
	}
	_, addr, err = daemonClientFromEnv(context.Background(), daemonEnv, nil, refuse)
	if err == nil || !strings.Contains(err.Error(), envDaemonSPIFFEID) || addr != "gibson:50051" {
		t.Errorf("client error: addr=%q err=%v, want the address and an error that names %s", addr, err, envDaemonSPIFFEID)
	}
}
