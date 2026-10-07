// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package timelinearchive

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestObjectKey_IsUnderTheAuditPrefixAndSortsInStreamOrder(t *testing.T) {
	a := ObjectKey("acme", StreamID{Ms: 9, Seq: 0}, StreamID{Ms: 10, Seq: 2})
	b := ObjectKey("acme", StreamID{Ms: 11, Seq: 0}, StreamID{Ms: 12, Seq: 0})
	assert.True(t, strings.HasPrefix(a, audit.ExportPrefix+"acme/timeline/"), a)
	assert.Less(t, a, b, "a later range must sort after an earlier range")
	assert.Equal(t, a, ObjectKey("acme", StreamID{Ms: 9}, StreamID{Ms: 10, Seq: 2}), "the name depends on the range only")
}

func TestNew_RefusesAMissingDependencyAndABadLock(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	db := &sql.DB{}
	var p fakePool
	periods := fixedPeriod{months: 13}

	_, err := New(db, nil, periods, nil, audit.ExportPolicy{}, logger)
	require.Error(t, err, "a nil pool is refused")

	_, err = New(db, p, nil, nil, audit.ExportPolicy{}, logger)
	require.Error(t, err, "a nil period source is refused")

	_, err = New(db, p, periods, nil, audit.ExportPolicy{}, logger)
	require.NoError(t, err, "with no store, no lock policy is needed")

	_, err = New(db, p, periods, fakeStore{}, audit.ExportPolicy{LockMode: "NONE", LockDays: 1}, logger)
	require.Error(t, err, "a store needs a valid lock policy")
}

type fakePool struct{}

func (fakePool) For(context.Context, auth.TenantID) (TenantDB, error) { return nil, nil }

type fakeStore struct{}

func (fakeStore) PutLocked(context.Context, string, []byte, audit.ObjectLock) error { return nil }

type fixedPeriod struct{ months int }

func (f fixedPeriod) Period(context.Context, string) (audit.RetentionPeriod, error) {
	return audit.RetentionPeriod{InstallMonths: f.months, EffectiveMonths: f.months}, nil
}
