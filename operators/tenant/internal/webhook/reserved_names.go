/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReservedNamesConfigMap is the chart-managed ConfigMap that holds the
// reserved-tenant-names denylist. The chart writes it under
// templates/gibson/reserved-names-configmap.yaml in the gibson namespace.
const ReservedNamesConfigMap = "gibson-reserved-names"

// ConfigMapReservedNames is a controller-runtime-client backed
// ReservedNamesProvider with a 30-second in-process cache. NotFound is
// treated as an empty denylist (the chart deployment may have wiped the
// ConfigMap or upgraded out of sync — the dashboard signup form is the
// secondary gate).
//
// Safe for concurrent use.
type ConfigMapReservedNames struct {
	Client    client.Client
	Namespace string
	TTL       time.Duration

	mu      sync.Mutex
	expires time.Time
	exact   []string
	prefix  []string
}

// NewConfigMapReservedNames returns a ReservedNamesProvider backed by the
// gibson-reserved-names ConfigMap in `namespace`. ttl bounds cache age;
// pass 0 for the 30-second default.
func NewConfigMapReservedNames(c client.Client, namespace string, ttl time.Duration) *ConfigMapReservedNames {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &ConfigMapReservedNames{Client: c, Namespace: namespace, TTL: ttl}
}

// LookupNamespace returns the namespace the operator pod is running in,
// preferring POD_NAMESPACE → OPERATOR_NAMESPACE → "gibson".
func LookupNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	if ns := os.Getenv("OPERATOR_NAMESPACE"); ns != "" {
		return ns
	}
	return "gibson"
}

// ReservedNames implements ReservedNamesProvider. NotFound = empty
// denylist (no error). Other errors are surfaced; callers may opt to
// treat them as failure-open (the validator does).
func (r *ConfigMapReservedNames) ReservedNames(ctx context.Context) ([]string, []string, error) {
	if r == nil {
		return nil, nil, errors.New("webhook: nil ConfigMapReservedNames")
	}
	r.mu.Lock()
	if time.Now().Before(r.expires) {
		exact := append([]string(nil), r.exact...)
		prefix := append([]string(nil), r.prefix...)
		r.mu.Unlock()
		return exact, prefix, nil
	}
	r.mu.Unlock()

	var cm corev1.ConfigMap
	key := types.NamespacedName{Namespace: r.Namespace, Name: ReservedNamesConfigMap}
	if err := r.Client.Get(ctx, key, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			r.store(nil, nil)
			return nil, nil, nil
		}
		return nil, nil, err
	}
	exact := parseList(cm.Data["exact"])
	prefix := parseList(cm.Data["prefix"])
	r.store(exact, prefix)
	return exact, prefix, nil
}

func (r *ConfigMapReservedNames) store(exact, prefix []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exact = exact
	r.prefix = prefix
	r.expires = time.Now().Add(r.TTL)
}

func parseList(raw string) []string {
	if raw == "" {
		return nil
	}
	out := make([]string, 0)
	for line := range strings.SplitSeq(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
