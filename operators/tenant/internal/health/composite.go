// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// CompositeTimeout is the outer budget for all sub-checks running concurrently.
	CompositeTimeout = 2 * time.Second

	statusOK      = "ok"
	statusSkipped = "skipped"
)

// pingFn is a function that performs a single subsystem ping. A nil pingFn
// causes the check to be skipped.
type pingFn func(ctx context.Context) error

// Dep describes a single downstream dependency to probe.
type Dep struct {
	// Name is the key used in the JSON summary (e.g. "dashboard", "fga").
	Name string
	// Ping is the probe function. A nil Ping marks the check as "skipped".
	Ping pingFn
}

// Summary is the JSON body emitted by the readyz handler on both success and
// failure so operators can identify which subsystem is red.
type Summary struct {
	OK     bool              `json:"ok"`
	Checks map[string]string `json:"checks"`
}

// compositeError wraps a Summary so the caller can retrieve structured
// diagnostics from the error value returned by Composite.Check.
type compositeError struct {
	summary Summary
}

func (e *compositeError) Error() string {
	b, _ := json.Marshal(e.summary)
	return string(b)
}

// Composite runs a set of downstream Dep pings concurrently under a shared
// timeout and produces a Summary. It plugs into controller-runtime's
// AddReadyzCheck via the Checker method.
type Composite struct {
	deps    []Dep
	timeout time.Duration
}

// NewComposite constructs a Composite probe with the given dependencies and
// outer timeout. If timeout is zero CompositeTimeout is used.
func NewComposite(deps []Dep, timeout time.Duration) *Composite {
	if timeout <= 0 {
		timeout = CompositeTimeout
	}
	return &Composite{deps: deps, timeout: timeout}
}

// Run executes all pings concurrently under the composite timeout and returns
// the Summary. Callers that only need the structured result use this method
// directly; the Checker method adapts it to the controller-runtime interface.
func (c *Composite) Run(ctx context.Context) Summary {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	type result struct {
		name   string
		status string
	}

	results := make([]result, len(c.deps))
	var wg sync.WaitGroup
	wg.Add(len(c.deps))
	for i, dep := range c.deps {
		go func() {
			defer wg.Done()
			if dep.Ping == nil {
				results[i] = result{name: dep.Name, status: statusSkipped}
				return
			}
			if err := dep.Ping(ctx); err != nil {
				results[i] = result{name: dep.Name, status: fmt.Sprintf("error:%s", err.Error())}
				return
			}
			results[i] = result{name: dep.Name, status: statusOK}
		}()
	}
	wg.Wait()

	summary := Summary{
		OK:     true,
		Checks: make(map[string]string, len(results)),
	}
	for _, r := range results {
		summary.Checks[r.name] = r.status
		if r.status != statusOK && r.status != statusSkipped {
			summary.OK = false
		}
	}
	return summary
}

// Checker satisfies the controller-runtime healthz.Checker type
// (func(*http.Request) error). On failure it returns a *compositeError whose
// Error() string is the JSON Summary — visible in kubectl describe and logs.
// On success it returns nil and controller-runtime writes "ok".
func (c *Composite) Checker(req *http.Request) error {
	summary := c.Run(req.Context())
	if !summary.OK {
		return &compositeError{summary: summary}
	}
	return nil
}

// ServeHTTP implements http.Handler. It always writes the JSON Summary body
// with an appropriate status code (200 or 503). Wire this to a dedicated path
// when you need machine-readable readyz output (e.g. operator dashboards).
func (c *Composite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	summary := c.Run(r.Context())
	body, _ := json.Marshal(summary)
	w.Header().Set("Content-Type", "application/json")
	if !summary.OK {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.Write(body)
}
