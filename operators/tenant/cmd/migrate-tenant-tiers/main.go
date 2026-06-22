/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Command migrate-tenant-tiers iterates every Tenant CR and rewrites
// spec.tier from any legacy plan id to the canonical four (team / org /
// enterprise / enterprise-deploy).
//
// As of Phase 5.3 of deploy-architecture-refactor, this binary is a
// thin wrapper around internal/backfill/tiermigrate.Run, which is also
// invoked as a startup Runnable inside the operator (see
// internal/startup/backfills.go). The standalone CLI is kept for
// ad-hoc operator runs (e.g. troubleshooting); the canonical execution
// is via the operator's manager.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	tiermigrate "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/tiermigrate"
)

func main() {
	var (
		dryRun  bool
		workers int
		timeout time.Duration
	)
	flag.BoolVar(&dryRun, "dry-run", false, "list tenants that would be migrated without modifying anything")
	flag.IntVar(&workers, "workers", 8, "parallelism for per-tenant patch")
	flag.DurationVar(&timeout, "timeout", 10*time.Minute, "overall deadline for the run")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gibsonv1alpha1.AddToScheme(scheme))

	cfg, err := loadKubeConfig()
	if err != nil {
		logger.Error("kube config", "err", err)
		os.Exit(1)
	}
	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error("kube client", "err", err)
		os.Exit(1)
	}

	if err := tiermigrate.Run(ctx, cl, tiermigrate.Options{
		DryRun:  dryRun,
		Workers: workers,
	}); err != nil {
		logger.Error("migrate-tenant-tiers failed", "err", err)
		os.Exit(1)
	}
	logger.Info("migrate-tenant-tiers complete")
}

func loadKubeConfig() (*rest.Config, error) {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}
	return ctrl.GetConfig()
}
