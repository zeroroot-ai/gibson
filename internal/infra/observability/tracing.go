// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"time"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// tracingOptions holds configuration options for tracing initialization.
type tracingOptions struct {
	sampler      sdktrace.Sampler
	resource     *resource.Resource
	batchTimeout time.Duration
}
