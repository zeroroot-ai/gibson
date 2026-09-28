// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconn_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// TestSetupLinkURLTemplate_NamesTheLoginVerifyPage pins the link to the page
// and the query parameter names Zitadel's Login v2 verify page reads
// (userId, code, invite, organization). /invite does not exist there.
func TestSetupLinkURLTemplate_NamesTheLoginVerifyPage(t *testing.T) {
	got := zitadelconn.SetupLinkURLTemplate("https://app.staging.zeroroot.ai/")
	rendered := strings.NewReplacer("{{.UserID}}", "U1", "{{.Code}}", "C1", "{{.OrgID}}", "O1").Replace(got)
	u, err := url.Parse(rendered)
	if err != nil {
		t.Fatalf("parse %q: %v", rendered, err)
	}
	if u.Scheme != "https" || u.Host != "app.staging.zeroroot.ai" || u.Path != "/ui/v2/login/verify" {
		t.Fatalf("link = %q, want https://app.staging.zeroroot.ai/ui/v2/login/verify", rendered)
	}
	q := u.Query()
	for k, want := range map[string]string{"userId": "U1", "code": "C1", "invite": "true", "organization": "O1"} {
		if q.Get(k) != want {
			t.Errorf("query %s = %q, want %q (link %q)", k, q.Get(k), want, rendered)
		}
	}
	if q.Has("userID") {
		t.Errorf("link %q uses userID; the verify page reads userId", rendered)
	}
}
