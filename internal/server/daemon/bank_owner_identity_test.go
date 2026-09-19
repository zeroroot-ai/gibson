// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"

	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// A SPIFFE caller's subject carries a scheme the FGA checks strip. What
// CreateBank and OpenJob write must be what authorize reads, or the caller
// cannot read the bank it just created (gibson#13, run 35443640498).
const spiffeCaller = "spiffe://zeroroot.ai/platform/e2e-runner"

func TestCreateBank_SPIFFECallerOwnsWhatItCanRead(t *testing.T) {
	store, az := newFakeBankStore(), &fakeAuthorizer{}
	srv := bankTestServer(t, store, az, nil)
	ctx := bankCtx(t, "acme", spiffeCaller)

	resp, err := srv.CreateBank(ctx, apiKeyBank("nightly"))
	if err != nil {
		t.Fatalf("CreateBank: %v", err)
	}
	var owner string
	for _, tp := range az.written {
		if tp.Relation == "owner" {
			owner = tp.User
		}
	}
	if owner != "user:zeroroot.ai/platform/e2e-runner" {
		t.Fatalf("owner tuple user = %q, want the FGA user the checks read", owner)
	}
	if got := resp.GetBank().GetOwner().GetId(); got != "zeroroot.ai/platform/e2e-runner" {
		t.Fatalf("owner id = %q, want the same id without the type", got)
	}

	az.checks = nil
	if _, err := srv.ListMembers(ctx, &bankpb.ListMembersRequest{BankId: resp.GetBank().GetId()}); err != nil {
		t.Fatalf("ListMembers by the owner: %v", err)
	}
	if len(az.checks) == 0 || !strings.HasPrefix(az.checks[0], owner+"|") {
		t.Fatalf("the read checked %v, want the user the owner tuple names (%s)", az.checks, owner)
	}
}

func TestOpenJob_SPIFFEOpenerIsTheUserTheChecksRead(t *testing.T) {
	srv, _, banks, az := jobTestServer(t)
	ctx := bankCtx(t, "acme", spiffeCaller)
	bankID := seededBankID(t, banks)

	if _, err := srv.OpenJob(ctx, &jobpb.OpenJobRequest{BankId: bankID, Spec: goodSpec()}); err != nil {
		t.Fatalf("OpenJob: %v", err)
	}
	var opener string
	for _, tp := range az.written {
		if tp.Relation == "opened_by" {
			opener = tp.User
		}
	}
	if opener != "user:zeroroot.ai/platform/e2e-runner" {
		t.Fatalf("opened_by tuple user = %q, want the FGA user the checks read", opener)
	}
}
