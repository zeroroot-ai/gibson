//go:build integration
// +build integration

package authz_test

import (
	"context"
	"testing"

	fgasdk "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/require"
)

// newRawFGAClient creates an FGA SDK client without a store ID (for management operations
// like CreateStore and WriteAuthorizationModel).
func newRawFGAClient(t *testing.T, baseURL string) *fgaclient.OpenFgaClient {
	t.Helper()

	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl: baseURL,
	})
	require.NoError(t, err, "failed to construct management FGA client")
	return c
}

// writeTestModel writes the Gibson authorization model (types: user, tenant, component, system_tenant)
// to the given FGA store and returns the resulting model ID.
//
// We define the model inline as a Go struct rather than parsing the .fga DSL file,
// since the OpenFGA CLI parser is a separate binary and not a Go library.
// The model must be semantically equivalent to core/gibson/internal/authz/model.fga.
func writeTestModel(t *testing.T, ctx context.Context, baseURL, storeID string) string {
	t.Helper()

	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:  baseURL,
		StoreId: storeID,
	})
	require.NoError(t, err)

	// Build the model programmatically, mirroring model.fga exactly.
	userRelation := "user"
	tenantType := "tenant"
	componentType := "component"
	systemTenantType := "system_tenant"

	// user type — no relations
	userTypeDef := fgasdk.TypeDefinition{
		Type:      userRelation,
		Relations: &map[string]fgasdk.Userset{},
	}

	// tenant type — admin: [user], member: [user] or admin
	memberComputed := "admin"
	tenantTypeDef := fgasdk.TypeDefinition{
		Type: tenantType,
		Relations: &map[string]fgasdk.Userset{
			"admin": {
				This: &map[string]interface{}{},
			},
			"member": {
				Union: &fgasdk.Usersets{
					Child: []fgasdk.Userset{
						{This: &map[string]interface{}{}},
						{ComputedUserset: &fgasdk.ObjectRelation{
							Relation: &memberComputed,
						}},
					},
				},
			},
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"admin": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userRelation},
					},
				},
				"member": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userRelation},
					},
				},
			},
		},
	}

	// component type — owner: [tenant], can_execute/can_configure: [user, tenant#member] or admin from owner
	ownerRelation := "owner"
	adminRelation := "admin"
	canExecuteTypeDef := fgasdk.Userset{
		Union: &fgasdk.Usersets{
			Child: []fgasdk.Userset{
				{This: &map[string]interface{}{}},
				{TupleToUserset: &fgasdk.TupleToUserset{
					Tupleset:        fgasdk.ObjectRelation{Relation: &ownerRelation},
					ComputedUserset: fgasdk.ObjectRelation{Relation: &adminRelation},
				}},
			},
		},
	}

	componentTypeDef := fgasdk.TypeDefinition{
		Type: componentType,
		Relations: &map[string]fgasdk.Userset{
			"owner":         {This: &map[string]interface{}{}},
			"can_execute":   canExecuteTypeDef,
			"can_configure": canExecuteTypeDef, // same structure
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"owner": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: tenantType},
					},
				},
				"can_execute": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userRelation},
						{Type: tenantType, Relation: fgasdk.PtrString("member")},
					},
				},
				"can_configure": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userRelation},
						{Type: tenantType, Relation: fgasdk.PtrString("member")},
					},
				},
			},
		},
	}

	// system_tenant type — platform_operator: [user]
	systemTenantTypeDef := fgasdk.TypeDefinition{
		Type: systemTenantType,
		Relations: &map[string]fgasdk.Userset{
			"platform_operator": {This: &map[string]interface{}{}},
		},
		Metadata: &fgasdk.Metadata{
			Relations: &map[string]fgasdk.RelationMetadata{
				"platform_operator": {
					DirectlyRelatedUserTypes: &[]fgasdk.RelationReference{
						{Type: userRelation},
					},
				},
			},
		},
	}

	writeResp, err := c.WriteAuthorizationModel(ctx).Body(fgasdk.WriteAuthorizationModelRequest{
		SchemaVersion: "1.1",
		TypeDefinitions: []fgasdk.TypeDefinition{
			userTypeDef,
			tenantTypeDef,
			componentTypeDef,
			systemTenantTypeDef,
		},
	}).Execute()
	require.NoError(t, err, "failed to write authorization model")

	modelID := writeResp.GetAuthorizationModelId()
	require.NotEmpty(t, modelID, "model ID must not be empty after write")
	return modelID
}
