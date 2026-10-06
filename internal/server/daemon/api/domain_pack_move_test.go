// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// memImportStore keeps imported packs in memory, with the version rule of
// ontology.ImportStore.
type memImportStore struct {
	mu    sync.Mutex
	packs map[string]ontology.DomainPack
	err   error
}

func (m *memImportStore) Save(_ context.Context, pack *ontology.DomainPack, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.packs == nil {
		m.packs = map[string]ontology.DomainPack{}
	}
	if old, ok := m.packs[pack.Name]; ok && old.Version >= pack.Version {
		return ontology.ErrPackExists
	}
	m.packs[pack.Name] = *pack
	return nil
}

// memFragmentWriter records audit events and gives each one an id.
type memFragmentWriter struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (m *memFragmentWriter) WriteSyncID(_ context.Context, ev audit.Event) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return 0, m.err
	}
	m.events = append(m.events, ev)
	return int64(100 + len(m.events)), nil
}

func ownerIdentityCtx(subject string) context.Context {
	tid, _ := auth.NewTenantID("system")
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject, Tenant: tid})
}

// promoteForTest makes label a live extension of tenant acme.
func promoteForTest(t *testing.T, s *OntologyExtensionService, kind taxonomy.ProposalKind, label string) {
	t.Helper()
	proposeNTimes(context.Background(), t, s.registry.For("acme"), kind, label, taxonomy.MinRecurrenceForSettlement)
	k := tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL
	if kind == taxonomy.ProposedRelationshipType {
		k = tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_RELATIONSHIP_TYPE
	}
	_, err := s.ApproveOntologyExtensionProposal(ownerCtx("acme", "owner-1"),
		&tenantv1.ApproveOntologyExtensionProposalRequest{Kind: k, Label: label})
	require.NoError(t, err)
	p := waitForOntologyProposal(t, s.registry.For("acme"), label, brain.OntologyProposalApproved)
	require.True(t, p.Promoted)
}

// TestPackMovesBetweenInstalls: install A exports the live extensions of a
// tenant, and the Platform owner of install B imports the JSON.
func TestPackMovesBetweenInstalls(t *testing.T) {
	ext, _ := newOntologyExtensionService(t)
	promoteForTest(t, ext, taxonomy.ProposedNodeLabel, "Container")
	promoteForTest(t, ext, taxonomy.ProposedRelationshipType, "RUNS_IN")

	// Install A: the Domain Pack service shares the brain registry.
	a := NewDomainPackService(ext.registry, ontology.NewDomainPackCatalog(), &stubCatalogGate{}, &memImportStore{})
	out, err := a.ExportDomainPack(tenantCtx("acme"), &tenantv1.ExportDomainPackRequest{Name: "k8s", Version: 1})
	require.NoError(t, err)
	var exported ontology.DomainPack
	require.NoError(t, json.Unmarshal(out.GetPackJson(), &exported))
	assert.Equal(t, "k8s", exported.Name)
	assert.Equal(t, "acme", exported.Author)
	assert.Contains(t, exported.TaxonomyNodeLabels, "Container")
	assert.Contains(t, exported.TaxonomyRelationshipTypes, "RUNS_IN")
	assert.Contains(t, exported.TaxonomyNodeIdentity, "Container")

	// Install B.
	store := &memImportStore{}
	b, _ := newDomainPackServiceWithGate(t, ontology.NewDomainPackCatalog(), &stubCatalogGate{})
	b.imports = store
	resp, err := b.ImportDomainPack(ownerIdentityCtx("platform-owner"), &tenantv1.ImportDomainPackRequest{PackJson: out.GetPackJson()})
	require.NoError(t, err)
	assert.Equal(t, "k8s", resp.GetName())
	assert.Equal(t, int32(1), resp.GetVersion())
	assert.Contains(t, store.packs, "k8s")

	// The same version again is refused.
	_, err = b.ImportDomainPack(ownerIdentityCtx("platform-owner"), &tenantv1.ImportDomainPackRequest{PackJson: out.GetPackJson()})
	assert.Equal(t, codes.AlreadyExists, grpcCode(err))
}

func TestExportDomainPack_Refusals(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	_, err := s.ExportDomainPack(context.Background(), &tenantv1.ExportDomainPackRequest{Name: "k8s", Version: 1})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
	_, err = s.ExportDomainPack(tenantCtx("acme"), &tenantv1.ExportDomainPackRequest{Name: "bad name", Version: 1})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	_, err = s.ExportDomainPack(tenantCtx("acme"), &tenantv1.ExportDomainPackRequest{Name: "k8s"})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestImportDomainPack_Refusals(t *testing.T) {
	s, _ := newDomainPackService(t, ontology.NewDomainPackCatalog())
	ctx := ownerIdentityCtx("platform-owner")
	cases := map[string]struct {
		ctx  context.Context
		json string
		want codes.Code
	}{
		"no identity":      {context.Background(), `{"name":"p","version":1}`, codes.PermissionDenied},
		"not JSON":         {ctx, `{`, codes.InvalidArgument},
		"unknown field":    {ctx, `{"name":"p","version":1,"oops":1}`, codes.InvalidArgument},
		"no name":          {ctx, `{"version":1}`, codes.InvalidArgument},
		"an embedded pack": {ctx, `{"name":"main","version":9}`, codes.AlreadyExists},
		"bad predicate":    {ctx, `{"name":"p","version":1,"predicates":{"t":"evidence +"}}`, codes.InvalidArgument},
		"bad mapping rule": {ctx, `{"name":"p","version":1,"controls":[{"id":"ac-2","title":"t","family":"ac","family_title":"t"}],"mapping_rules":[{"control_id":"ac-2","expression":"evidence.size() > 0"}]}`, codes.InvalidArgument},
		"no key form":      {ctx, `{"name":"p","version":1,"taxonomy_node_labels":["Pod"]}`, codes.InvalidArgument},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.ImportDomainPack(tc.ctx, &tenantv1.ImportDomainPackRequest{PackJson: []byte(tc.json)})
			assert.Equal(t, tc.want, grpcCode(err))
		})
	}
	t.Run("the store fails", func(t *testing.T) {
		s.imports = &memImportStore{err: errors.New("db down")}
		_, err := s.ImportDomainPack(ctx, &tenantv1.ImportDomainPackRequest{PackJson: []byte(`{"name":"p","version":1}`)})
		assert.Equal(t, codes.Internal, grpcCode(err))
	})
}

// TestSubmitOntologyExtensionUpstream_WritesTheFragmentAsAnAuditRecord: the
// fragment goes to one audit record, and the response names it.
func TestSubmitOntologyExtensionUpstream_WritesTheFragmentAsAnAuditRecord(t *testing.T) {
	s, _ := newOntologyExtensionService(t)
	w := &memFragmentWriter{}
	s.audit = w
	promoteForTest(t, s, taxonomy.ProposedNodeLabel, "Container")

	caller := subjectCtx(t, "acme", "owner-1")
	resp, err := s.SubmitOntologyExtensionUpstream(caller, &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	require.NoError(t, err)
	assert.Equal(t, "101", resp.GetAuditRecordId())
	require.Len(t, w.events, 1)
	ev := w.events[0]
	assert.Equal(t, SubmittedFragmentAction, ev.Action)
	assert.Equal(t, "acme", ev.TenantID)
	assert.Equal(t, "Container", ev.TargetID)
	assert.Equal(t, "owner-1", ev.ActorID)
	pack, err := ontology.DecodePackJSON(ev.Metadata)
	require.NoError(t, err)
	assert.Equal(t, []string{"Container"}, pack.TaxonomyNodeLabels)

	w.err = errors.New("postgres down")
	_, err = s.SubmitOntologyExtensionUpstream(caller, &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	assert.Equal(t, codes.Unavailable, grpcCode(err))

	// A caller with a tenant and no subject gets no record with an empty actor.
	w.err = nil
	_, err = s.SubmitOntologyExtensionUpstream(auth.ContextWithTenantString(context.Background(), "acme"), &tenantv1.SubmitOntologyExtensionUpstreamRequest{
		Kind: tenantv1.OntologyProposalKind_ONTOLOGY_PROPOSAL_KIND_NODE_LABEL, Label: "Container",
	})
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))
	assert.Len(t, w.events, 1, "no second record")
}

// TestPackMoveAuthzEntries pins the authorization of the two RPCs.
func TestPackMoveAuthzEntries(t *testing.T) {
	exp := registry.Registry["/gibson.tenant.v1.DomainPackService/ExportDomainPack"]
	assert.Equal(t, "admin", exp.Relation)
	assert.Equal(t, "tenant", exp.ObjectType)
	imp := registry.Registry["/gibson.tenant.v1.DomainPackService/ImportDomainPack"]
	assert.Equal(t, "platform_owner", imp.Relation)
	assert.Equal(t, "system_tenant", imp.ObjectType)
	assert.Equal(t, registry.IdentityUser, imp.AllowedIdentities)
}

// subjectCtx is a caller context of tenantID with a verified identity whose
// subject is subject.
func subjectCtx(t *testing.T, tenantID, subject string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(tenantID)
	require.NoError(t, err)
	return auth.WithIdentity(tenantCtx(tenantID), auth.Identity{Subject: subject, Tenant: tid})
}
