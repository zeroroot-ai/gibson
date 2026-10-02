// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package resolver

// mockComponentStore lived in manifest_loader_test.go until the manifest loader
// left with the component.yaml schema (gibson#555). The resolver tests still
// need a store double.

import (
	"context"
	"errors"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// mockComponentStore is a test double for component.ComponentStore
type mockComponentStore struct {
	components map[string]*component.Component
	err        error
}

func newMockComponentStore() *mockComponentStore {
	return &mockComponentStore{
		components: make(map[string]*component.Component),
	}
}

func (m *mockComponentStore) key(kind component.ComponentKind, name string) string {
	return string(kind) + ":" + name
}

func (m *mockComponentStore) add(comp *component.Component) {
	m.components[m.key(comp.Kind, comp.Name)] = comp
}

func (m *mockComponentStore) GetByName(_ context.Context, kind component.ComponentKind, name string) (*component.Component, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.components[m.key(kind, name)], nil
}

// The remaining ComponentStore methods are not exercised by the resolver tests;
// each answers with an error rather than a silent nil.
func (m *mockComponentStore) Create(context.Context, *component.Component) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) List(context.Context, component.ComponentKind) ([]*component.Component, error) {
	return nil, errors.New("not implemented")
}

func (m *mockComponentStore) ListAll(context.Context) (map[component.ComponentKind][]*component.Component, error) {
	return nil, errors.New("not implemented")
}

func (m *mockComponentStore) Update(context.Context, *component.Component) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) Delete(context.Context, component.ComponentKind, string) error {
	return errors.New("not implemented")
}

func (m *mockComponentStore) ListInstances(context.Context, component.ComponentKind, string) ([]component.ComponentInfo, error) {
	return nil, errors.New("not implemented")
}
