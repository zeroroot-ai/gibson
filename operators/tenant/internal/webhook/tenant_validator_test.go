// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package webhook

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// validTenant returns a Tenant object that satisfies all validation rules.
func validTenant() *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acme-corp",
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: "Acme Corp",
			Owner:       "admin@acme.com",
			Tier:        gibsonv1alpha1.TenantPlanTeam,
		},
	}
}

// --- slug tests ---

func TestValidateSlug_Valid(t *testing.T) {
	cases := []string{
		"a",
		"abc",
		"my-tenant",
		"tenant-01",
		"a1b2c3",
		// exactly 60 chars: 1 leading + 58 interior + 1 trailing
		"a" + strings.Repeat("b", 58) + "c",
	}
	for _, slug := range cases {
		t.Run(slug, func(t *testing.T) {
			if err := validateSlug(slug); err != nil {
				t.Errorf("expected valid slug %q to pass, got: %v", slug, err)
			}
		})
	}
}

func TestValidateSlug_Invalid(t *testing.T) {
	cases := []struct {
		slug string
		desc string
	}{
		{"", "empty"},
		{"-start", "leading hyphen"},
		{"end-", "trailing hyphen"},
		{"UPPER", "uppercase"},
		{"has space", "space"},
		{"has.dot", "dot"},
		{strings.Repeat("a", 61), "61 chars (too long)"},
		{"has_underscore", "underscore"},
		{"1abc", "leading digit"},
		{"9", "single digit"},
		{"2zeroroot-ai1", "leading digit (regression: daemon rejects identifiers starting with digit)"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if err := validateSlug(tc.slug); err == nil {
				t.Errorf("expected slug %q to be rejected (%s), but it passed", tc.slug, tc.desc)
			}
		})
	}
}

// --- owner / email tests ---

func TestValidateOwner_Valid(t *testing.T) {
	cases := []string{
		"admin@acme.com",
		"user+tag@example.org",
		"first.last@sub.domain.io",
		"test@localhost",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			if err := validateOwner(addr); err != nil {
				t.Errorf("expected %q to be valid, got: %v", addr, err)
			}
		})
	}
}

func TestValidateOwner_Invalid(t *testing.T) {
	cases := []struct {
		addr string
		desc string
	}{
		{"", "empty"},
		{"notanemail", "no @"},
		{"@nodomain", "no local part"},
		{"two@@ats.com", "double @"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if err := validateOwner(tc.addr); err == nil {
				t.Errorf("expected %q (%s) to be rejected, but it passed", tc.addr, tc.desc)
			}
		})
	}
}

// --- tier tests ---

func TestValidateTier_Valid(t *testing.T) {
	tiers := []gibsonv1alpha1.TenantTier{
		gibsonv1alpha1.TenantPlanTeam,
		gibsonv1alpha1.TenantPlanOrg,
		gibsonv1alpha1.TenantPlanEnterprise,
		gibsonv1alpha1.TenantPlanEnterpriseDeploy,
	}
	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			if err := validateTier(tier); err != nil {
				t.Errorf("expected tier %q to be valid, got: %v", tier, err)
			}
		})
	}
}

func TestValidateTier_Invalid(t *testing.T) {
	cases := []gibsonv1alpha1.TenantTier{
		"",
		"basic",
		"premium",
		"FREE",
		"Pro",
		// Legacy ids — chart's tenant-tier-migrate Job rewrites these to
		// canonical ids before this webhook starts rejecting them.
		"free",
		"pro",
		"solo",
		"squad",
		"platform",
		"enterprise-cloud",
		"enterprise-onprem",
		"public-sector",
	}
	for _, tier := range cases {
		t.Run(string(tier), func(t *testing.T) {
			if err := validateTier(tier); err == nil {
				t.Errorf("expected tier %q to be rejected, but it passed", tier)
			}
		})
	}
}

// --- displayName tests ---

func TestValidateDisplayName_Valid(t *testing.T) {
	cases := []string{
		"A",
		"Acme Corp",
		strings.Repeat("x", 120), // exactly at the limit
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateDisplayName(name); err != nil {
				t.Errorf("expected displayName %q to be valid, got: %v", name, err)
			}
		})
	}
}

func TestValidateDisplayName_Invalid(t *testing.T) {
	cases := []struct {
		name string
		desc string
	}{
		{"", "empty"},
		{strings.Repeat("x", 121), "121 chars (exceeds limit)"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if err := validateDisplayName(tc.name); err == nil {
				t.Errorf("expected displayName %q (%s) to be rejected, but it passed", tc.name, tc.desc)
			}
		})
	}
}

// --- ValidateCreate tests ---

func TestTenantValidator_ValidateCreate_Valid(t *testing.T) {
	v := &TenantValidator{}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err != nil {
		t.Fatalf("expected valid tenant to pass ValidateCreate, got: %v", err)
	}
}

func TestTenantValidator_ValidateCreate_MissingSlug(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Name = ""
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for empty slug, got nil")
	}
	if !strings.Contains(err.Error(), "metadata.name") {
		t.Errorf("expected error to mention metadata.name, got: %v", err)
	}
}

func TestTenantValidator_ValidateCreate_InvalidSlug(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Name = "INVALID-SLUG"
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for invalid slug, got nil")
	}
}

func TestTenantValidator_ValidateCreate_MissingOwner(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.Owner = ""
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for empty owner, got nil")
	}
	if !strings.Contains(err.Error(), "spec.owner") {
		t.Errorf("expected error to mention spec.owner, got: %v", err)
	}
}

func TestTenantValidator_ValidateCreate_InvalidOwner(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.Owner = "not-an-email"
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for invalid owner email, got nil")
	}
}

func TestTenantValidator_ValidateCreate_InvalidTier(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.Tier = "gold"
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for unknown tier, got nil")
	}
	if !strings.Contains(err.Error(), "spec.tier") {
		t.Errorf("expected error to mention spec.tier, got: %v", err)
	}
}

func TestTenantValidator_ValidateCreate_EmptyTier(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.Tier = ""
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for empty tier, got nil")
	}
}

func TestTenantValidator_ValidateCreate_MissingDisplayName(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.DisplayName = ""
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for empty displayName, got nil")
	}
	if !strings.Contains(err.Error(), "spec.displayName") {
		t.Errorf("expected error to mention spec.displayName, got: %v", err)
	}
}

func TestTenantValidator_ValidateCreate_DisplayNameTooLong(t *testing.T) {
	v := &TenantValidator{}
	tn := validTenant()
	tn.Spec.DisplayName = strings.Repeat("x", 121)
	_, err := v.ValidateCreate(context.Background(), tn)
	if err == nil {
		t.Fatal("expected rejection for displayName exceeding 120 chars, got nil")
	}
}

// --- ValidateUpdate tests ---

func TestTenantValidator_ValidateUpdate_Valid(t *testing.T) {
	v := &TenantValidator{}
	oldTn := validTenant()
	newTn := validTenant()
	// Changing tier and displayName is allowed on update.
	newTn.Spec.Tier = gibsonv1alpha1.TenantPlanEnterprise
	newTn.Spec.DisplayName = "Acme Corp Enterprise"
	_, err := v.ValidateUpdate(context.Background(), oldTn, newTn)
	if err != nil {
		t.Fatalf("expected valid update to pass, got: %v", err)
	}
}

func TestTenantValidator_ValidateUpdate_ImmutableSlug(t *testing.T) {
	v := &TenantValidator{}
	oldTn := validTenant()
	newTn := validTenant()
	newTn.Name = "new-slug"
	_, err := v.ValidateUpdate(context.Background(), oldTn, newTn)
	if err == nil {
		t.Fatal("expected rejection for slug change on update, got nil")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("expected 'immutable' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "metadata.name") {
		t.Errorf("expected 'metadata.name' in error, got: %v", err)
	}
}

func TestTenantValidator_ValidateUpdate_ImmutableOwner(t *testing.T) {
	v := &TenantValidator{}
	oldTn := validTenant()
	newTn := validTenant()
	newTn.Spec.Owner = "other@example.com"
	_, err := v.ValidateUpdate(context.Background(), oldTn, newTn)
	if err == nil {
		t.Fatal("expected rejection for owner change on update, got nil")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("expected 'immutable' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "spec.owner") {
		t.Errorf("expected 'spec.owner' in error, got: %v", err)
	}
}

func TestTenantValidator_ValidateUpdate_InvalidNewTier(t *testing.T) {
	v := &TenantValidator{}
	oldTn := validTenant()
	newTn := validTenant()
	newTn.Spec.Tier = "diamond"
	_, err := v.ValidateUpdate(context.Background(), oldTn, newTn)
	if err == nil {
		t.Fatal("expected rejection for invalid tier on update, got nil")
	}
}

func TestTenantValidator_ValidateUpdate_InvalidNewDisplayName(t *testing.T) {
	v := &TenantValidator{}
	oldTn := validTenant()
	newTn := validTenant()
	newTn.Spec.DisplayName = ""
	_, err := v.ValidateUpdate(context.Background(), oldTn, newTn)
	if err == nil {
		t.Fatal("expected rejection for empty displayName on update, got nil")
	}
}

// --- ValidateDelete tests ---

func TestTenantValidator_ValidateDelete_Always_Allowed(t *testing.T) {
	v := &TenantValidator{}
	// Even a completely invalid tenant object should be allowed to delete;
	// lifecycle protection is the finalizer's job.
	tn := &gibsonv1alpha1.Tenant{}
	_, err := v.ValidateDelete(context.Background(), tn)
	if err != nil {
		t.Fatalf("expected delete to always be allowed, got: %v", err)
	}
}

// --- slug boundary tests ---

func TestValidateSlug_BoundaryLengths(t *testing.T) {
	// single char — valid
	if err := validateSlug("a"); err != nil {
		t.Errorf("single char slug should be valid: %v", err)
	}
	// 60 chars — valid (1 + 58 + 1)
	slug60 := "a" + strings.Repeat("b", 58) + "c"
	if len(slug60) != 60 {
		t.Fatalf("test setup: expected 60-char slug, got %d", len(slug60))
	}
	if err := validateSlug(slug60); err != nil {
		t.Errorf("60-char slug should be valid: %v", err)
	}
	// 61 chars — invalid
	slug61 := slug60 + "d"
	if err := validateSlug(slug61); err == nil {
		t.Errorf("61-char slug should be rejected")
	}
}

// --- displayName boundary tests ---

func TestValidateDisplayName_BoundaryLengths(t *testing.T) {
	// 120 chars — valid
	name120 := strings.Repeat("x", 120)
	if err := validateDisplayName(name120); err != nil {
		t.Errorf("120-char displayName should be valid: %v", err)
	}
	// 121 chars — invalid
	name121 := strings.Repeat("x", 121)
	if err := validateDisplayName(name121); err == nil {
		t.Errorf("121-char displayName should be rejected")
	}
}
