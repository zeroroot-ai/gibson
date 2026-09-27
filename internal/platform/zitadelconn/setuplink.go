// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadelconn

import "strings"

// SetupLinkURLTemplate is the one invite-code link every gibson component
// asks Zitadel to email or writes to an offline Secret (ADR-0093 decision 8):
// the Platform owner, the first tenant's Owner and an accepted invitation.
//
// Zitadel's Login v2 app (apps/login, v4.18.0) has no /invite page. An invite
// code is redeemed on the verify page, which reads userId, code, organization
// and invite=true (apps/login/src/app/(login)/verify/page.tsx). A link to
// /invite with userID opened a 404 page (measured on kind, 2026-09-27).
//
// publicOrigin is the origin a person's browser reaches: "https://" plus the
// public host, or GIBSON_APP_URL. Never an issuer or ZITADEL_URL, which name
// the in-cluster Service on some profiles. Zitadel substitutes {{.UserID}},
// {{.Code}} and {{.OrgID}}.
func SetupLinkURLTemplate(publicOrigin string) string {
	return strings.TrimRight(publicOrigin, "/") +
		"/ui/v2/login/verify?userId={{.UserID}}&code={{.Code}}&invite=true&organization={{.OrgID}}"
}
