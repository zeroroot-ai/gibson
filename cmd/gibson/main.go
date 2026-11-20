// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/zeroroot-ai/gibson/pkg/gibsond"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Force-exit on second signal: after first signal ctx is cancelled,
	// a subsequent unhandled signal terminates the process immediately.
	go func() {
		<-ctx.Done()
		stop() // deregister so next SIGINT/SIGTERM is not captured
		select {}
	}()

	os.Exit(gibsond.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
