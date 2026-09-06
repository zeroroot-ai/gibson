// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package reconciler

import (
	"context"
	"sort"
)

// desiredKeys renders a desired set as sorted "tenant/connector" keys for
// stable comparison in catalog-source and token-reconciler tests.
func desiredKeys(d []ConnectorSandbox) []string {
	out := make([]string, 0, len(d))
	for _, c := range d {
		out = append(out, c.Tenant.String()+"/"+c.Connector)
	}
	sort.Strings(out)
	return out
}

// fakeCatalog is a CatalogSource stub returning a fixed desired set (or error).
type fakeCatalog struct {
	desired []ConnectorSandbox
	err     error
}

func (f *fakeCatalog) DesiredConnectors(context.Context) ([]ConnectorSandbox, error) {
	return f.desired, f.err
}
