// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefartifact

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStore_Put(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()

	mock.ExpectQuery("COALESCE\\(MAX\\(version\\), 0\\) \\+ 1").
		WithArgs("acme", `{"a":1}`, `{"b":2}`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(1)))
	if v, err := store.Put(ctx, "acme", []byte(`{"a":1}`), []byte(`{"b":2}`)); err != nil || v != 1 {
		t.Fatalf("Put = %d, %v; want version 1", v, err)
	}
	for name, args := range map[string][2][]byte{
		"model is an array": {[]byte(`[1]`), []byte(`{}`)},
		"edges not JSON":    {[]byte(`{}`), []byte(`nope`)},
	} {
		if _, err := store.Put(ctx, "acme", args[0], args[1]); !errors.Is(err, ErrNotJSONObject) {
			t.Errorf("%s: err = %v, want ErrNotJSONObject", name, err)
		}
	}
	if _, err := store.Put(ctx, "", []byte(`{}`), []byte(`{}`)); err == nil {
		t.Error("an empty tenant was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
