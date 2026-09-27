// Package controller is a testdata stand-in for the real
// operators/platform/internal/controller package. This file's path
// (.../controller/oidcclient_controller.go) is the orgmemberwrite guard's
// one file-level exemption: reconciling a machine user's OWN ORG_-prefixed
// administrator roles, never a tenant user's membership. It constructs the
// exact AddOrgMember/RemoveOrgMember call shape the violation fixture
// flags in every OTHER file, and it must NOT be flagged here.
package controller

import (
	"context"

	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

func reconcileMachineUserOrgRoles(ctx context.Context, zc zitadel.Client, orgID, userID string, roles []string) error {
	if len(roles) == 0 {
		return zc.RemoveOrgMember(ctx, orgID, userID)
	}
	return zc.AddOrgMember(ctx, orgID, userID, roles)
}
