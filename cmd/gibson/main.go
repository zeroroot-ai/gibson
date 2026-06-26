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

	// OSS gibson sets no ENTITLEMENTS_ENDPOINT, so the daemon boots with the
	// config-driven Entitlements default. A hosted build activates the closed
	// billing service by setting the ENTITLEMENTS_ENDPOINT env var in the Helm
	// chart (Option B runtime seam, gibson#1028).
	os.Exit(gibsond.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
