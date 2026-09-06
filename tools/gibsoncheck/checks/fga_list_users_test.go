// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
)

// TestFGAListUsers_Rules covers R1, R2 and R3 against the fixture
// model, together with the negative controls that distinguish a genuine
// model-aware guard from a hardcoded denylist of relation names:
// team.member (a userset recursing into team#admin) and
// component.can_execute (difference over intersection over
// tuple-to-userset) both resolve TRUE and must stay silent.
func TestFGAListUsers_Rules(t *testing.T) {
	setFixtureModel(t)
	analysistest.Run(t, analysistest.TestData(), checks.FGAListUsersAnalyzer,
		"github.com/zeroroot-ai/gibson/internal/server/admin/fgalistusers")
}

// TestFGAListUsers_FailsClosedWithoutModel is the guard-integrity arm.
// A guard whose failure mode is "silently finds nothing" is the same
// defect class it was built to prevent, so an absent or unparseable
// model must produce an ERROR rather than a clean, empty run.
func TestFGAListUsers_FailsClosedWithoutModel(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		if err := checks.LoadFGAModelForTest(filepath.Join(t.TempDir(), "absent.fga")); err == nil {
			t.Fatal("model load succeeded for a path that does not exist; the analyzer must refuse to run rather than report zero findings")
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "broken.fga")
		if err := os.WriteFile(bad, []byte("this is not an FGA model\n"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if err := checks.LoadFGAModelForTest(bad); err == nil {
			t.Fatal("model load succeeded for an unparseable model; a silently-empty model would make every call site look clean")
		}
	})

	t.Run("valid", func(t *testing.T) {
		good, err := filepath.Abs(filepath.Join(analysistest.TestData(), "fga", "model.fga"))
		if err != nil {
			t.Fatalf("resolve fixture model: %v", err)
		}
		if err := checks.LoadFGAModelForTest(good); err != nil {
			t.Fatalf("fixture model must load cleanly: %v", err)
		}
	})
}

// setFixtureModel points the analyzer at the fixture model and clears
// the process-wide parsed-model cache so tests do not leak state.
func setFixtureModel(t *testing.T) {
	t.Helper()
	resetFGAModel(t)
	abs, err := filepath.Abs(filepath.Join(analysistest.TestData(), "fga", "model.fga"))
	if err != nil {
		t.Fatalf("resolve fixture model: %v", err)
	}
	if err := checks.FGAListUsersAnalyzer.Flags.Set("model", abs); err != nil {
		t.Fatalf("set model flag: %v", err)
	}
	t.Cleanup(func() { resetFGAModel(t); _ = checks.FGAListUsersAnalyzer.Flags.Set("model", "") })
}

func resetFGAModel(t *testing.T) {
	t.Helper()
	checks.ResetFGAModelForTest()
}
