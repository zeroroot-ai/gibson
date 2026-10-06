// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package compliance

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

type enabledSet map[string]bool

func (e enabledSet) IsDomainPackEnabled(_ context.Context, tenant, pack string) (bool, error) {
	return e[tenant+"/"+pack], nil
}

type failingEnabled struct{}

func (failingEnabled) IsDomainPackEnabled(context.Context, string, string) (bool, error) {
	return false, errors.New("world unavailable")
}

// testPack has three controls: one with a rule that matches grant changes,
// one with a rule that matches nothing in the fixture, and one with no rule.
func testPack() ontology.DomainPack {
	return ontology.DomainPack{
		Name:    "fw",
		Version: 3,
		Controls: []ontology.Control{
			{ID: "ac-2", Title: "Account Management", Family: "ac", FamilyTitle: "Access Control"},
			{ID: "ac-6", Title: "Least Privilege", Family: "ac", FamilyTitle: "Access Control"},
			{ID: "au-9", Title: "Protection of Audit Information", Family: "au", FamilyTitle: "Audit and Accountability"},
		},
		MappingRules: []ontology.MappingRule{
			{ControlID: "ac-2", Expression: `event.action == "never_recorded"`},
			{ControlID: "ac-6", Expression: `event.action in ["agent_grant_added", "agent_grant_removed"]`},
		},
	}
}

var (
	start = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end   = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

var auditColumns = []string{"id", "action", "target_type", "target_id", "decision", "actor_id", "actor_type", "created_at"}

// row is one audit_log row of the fixture.
func row(id int64, action string, at time.Time) []driver.Value {
	return []driver.Value{id, action, "agent_grant", "agent_principal:a", "allow", "user-1", "user", at}
}

func newTestReader(t *testing.T, rows [][]driver.Value, enabled EnabledPacks) *Reader {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	result := sqlmock.NewRows(auditColumns)
	for _, r := range rows {
		result.AddRow(r...)
	}
	mock.ExpectQuery("FROM   audit_log").WithArgs("acme", start, end).WillReturnRows(result)
	r, err := NewReader(db, ontology.NewDomainPackCatalog(testPack()), enabled)
	require.NoError(t, err)
	return r
}

func enabledFw() EnabledPacks { return enabledSet{"acme/fw": true} }

func TestEvidence_StatesCountsAndEvents(t *testing.T) {
	r := newTestReader(t, [][]driver.Value{
		row(10, "agent_grant_added", start.Add(time.Hour)),
		row(11, "plugin.enable", start.Add(2*time.Hour)),
		row(12, "agent_grant_removed", start.Add(3*time.Hour)),
	}, enabledFw())

	rep, err := r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "fw", Start: start, End: end})
	require.NoError(t, err)

	assert.Equal(t, "fw", rep.Pack)
	assert.Equal(t, 3, rep.PackVersion)
	assert.Equal(t, 2, rep.ControlsWithRule)
	assert.Equal(t, 3, rep.ControlsTotal)
	require.Len(t, rep.Controls, 3)

	assert.Equal(t, StateNoEvents, rep.Controls[0].State, "a rule with no event in the range")
	assert.Zero(t, rep.Controls[0].EventCount)
	assert.True(t, rep.Controls[0].LastEventTime.IsZero())

	assert.Equal(t, StateHasEvidence, rep.Controls[1].State)
	assert.Equal(t, int64(2), rep.Controls[1].EventCount)
	assert.Equal(t, start.Add(3*time.Hour), rep.Controls[1].LastEventTime)
	assert.Equal(t, "Access Control", rep.Controls[1].FamilyTitle)

	assert.Equal(t, StateNoRule, rep.Controls[2].State, "no rule is a different state from no event")

	require.Len(t, rep.Events, 2)
	assert.Equal(t, "10", rep.Events[0].AuditRecordID)
	assert.Equal(t, []string{"ac-6"}, rep.Events[0].ControlIDs)
	assert.Equal(t, "12", rep.Events[1].AuditRecordID)
	assert.Empty(t, rep.NextPageToken)
}

// TestEvidence_PagesARangeWithMoreEventsThanOnePage: five matching events,
// a page size of two. Three pages hold each event once, in order, and each
// page carries the counts of the whole range.
func TestEvidence_PagesARangeWithMoreEventsThanOnePage(t *testing.T) {
	var rows [][]driver.Value
	for i := int64(1); i <= 5; i++ {
		rows = append(rows, row(i, "agent_grant_added", start.Add(time.Duration(i)*time.Hour)))
	}
	var ids []string
	token := ""
	for page := range 3 {
		r := newTestReader(t, rows, enabledFw())
		rep, err := r.Evidence(context.Background(), Query{
			Tenant: "acme", Pack: "fw", Start: start, End: end, PageSize: 2, PageToken: token,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(5), rep.Controls[1].EventCount, "each page carries the counts of the whole range")
		for _, e := range rep.Events {
			ids = append(ids, e.AuditRecordID)
		}
		token = rep.NextPageToken
		if page < 2 {
			require.NotEmpty(t, token, "page %d must have a next page", page)
		}
	}
	assert.Empty(t, token, "the last page has no next page token")
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, ids)
}

func TestEvidence_RefusesATokenOfADifferentQuery(t *testing.T) {
	token, err := encodeCursor(pageCursor{Pack: "fw", Start: start.UnixMicro(), End: end.Add(time.Hour).UnixMicro(), AfterID: 3})
	require.NoError(t, err)
	r := newTestReader(t, nil, enabledFw())
	_, err = r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "fw", Start: start, End: end, PageToken: token})
	require.ErrorIs(t, err, ErrInvalidQuery)

	_, err = r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "fw", Start: start, End: end, PageToken: "!!"})
	require.ErrorIs(t, err, ErrInvalidQuery)
}

func TestEvidence_Refusals(t *testing.T) {
	cases := map[string]struct {
		q       Query
		enabled EnabledPacks
		want    error
	}{
		"no tenant":        {Query{Pack: "fw"}, enabledFw(), ErrInvalidQuery},
		"no pack":          {Query{Tenant: "acme"}, enabledFw(), ErrInvalidQuery},
		"end before start": {Query{Tenant: "acme", Pack: "fw", Start: end, End: start}, enabledFw(), ErrInvalidQuery},
		"negative page":    {Query{Tenant: "acme", Pack: "fw", PageSize: -1}, enabledFw(), ErrInvalidQuery},
		"unknown pack":     {Query{Tenant: "acme", Pack: "other"}, enabledFw(), ErrUnknownPack},
		"not enabled":      {Query{Tenant: "beta", Pack: "fw"}, enabledFw(), ErrPackNotEnabled},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			db, _, err := sqlmock.New()
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			r, err := NewReader(db, ontology.NewDomainPackCatalog(testPack()), tc.enabled)
			require.NoError(t, err)
			_, err = r.Evidence(context.Background(), tc.q)
			require.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("a pack with no control list", func(t *testing.T) {
		db, _, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		r, err := NewReader(db, ontology.NewDomainPackCatalog(ontology.DomainPack{Name: "plain"}), enabledSet{"acme/plain": true})
		require.NoError(t, err)
		_, err = r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "plain"})
		require.ErrorIs(t, err, ErrNotAFramework)
	})
	t.Run("the enabled packs source fails", func(t *testing.T) {
		db, _, err := sqlmock.New()
		require.NoError(t, err)
		defer func() { _ = db.Close() }()
		r, err := NewReader(db, ontology.NewDomainPackCatalog(testPack()), failingEnabled{})
		require.NoError(t, err)
		_, err = r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "fw"})
		require.ErrorContains(t, err, "world unavailable")
	})
}

func TestEvidence_DefaultRangeAndPageSize(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	r, err := NewReader(db, ontology.NewDomainPackCatalog(testPack()), enabledFw())
	require.NoError(t, err)
	r.now = func() time.Time { return end }
	q, _, err := r.normalize(Query{Tenant: "acme", Pack: "fw"})
	require.NoError(t, err)
	assert.Equal(t, end, q.End)
	assert.Equal(t, end.Add(-DefaultRange), q.Start)
	assert.Equal(t, DefaultPageSize, q.PageSize)
	q, _, err = r.normalize(Query{Tenant: "acme", Pack: "fw", PageSize: 10_000})
	require.NoError(t, err)
	assert.Equal(t, MaxPageSize, q.PageSize)
}

func TestNewReader_RequiresEachDependency(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	cat := ontology.NewDomainPackCatalog(testPack())
	_, err = NewReader(nil, cat, enabledFw())
	require.Error(t, err)
	_, err = NewReader(db, nil, enabledFw())
	require.Error(t, err)
	_, err = NewReader(db, cat, nil)
	require.Error(t, err)
}

// TestReport_HoldsNoVerdict pins the shape of the report: no field holds a
// verdict, a score or a percentage (D16).
func TestReport_HoldsNoVerdict(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[Report](), reflect.TypeFor[ControlEvidence](), reflect.TypeFor[EvidenceEvent](),
	} {
		for i := range typ.NumField() {
			name := strings.ToLower(typ.Field(i).Name)
			for _, banned := range []string{"verdict", "compliant", "score", "percent", "pass", "fail"} {
				assert.NotContainsf(t, name, banned, "%s.%s", typ.Name(), typ.Field(i).Name)
			}
		}
	}
}

// TestEvidence_TheNISTPackRuns: the embedded nist-800-53-r5 pack runs
// through the reader.
func TestEvidence_TheNISTPackRuns(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	mock.ExpectQuery("FROM   audit_log").WillReturnRows(
		sqlmock.NewRows(auditColumns).AddRow(row(1, "agent_grant_added", start.Add(time.Hour))...))
	r, err := NewReader(db, ontology.EmbeddedCatalog(), enabledSet{"acme/nist-800-53-r5": true})
	require.NoError(t, err)
	rep, err := r.Evidence(context.Background(), Query{Tenant: "acme", Pack: "nist-800-53-r5", Start: start, End: end})
	require.NoError(t, err)
	assert.Equal(t, 300, rep.ControlsTotal)
	require.Len(t, rep.Events, 1)
	assert.Equal(t, []string{"ac-6"}, rep.Events[0].ControlIDs)
}
