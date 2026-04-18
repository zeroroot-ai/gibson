//go:build integration
// +build integration

package authz_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fgasdk "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// loadModelFromDSL reads internal/authz/model.fga (the authoritative schema),
// transforms it to OpenFGA proto via openfga-language, and writes the result
// to the given store. Returns the new model ID. Using the DSL file directly
// here guarantees tests exercise the same model that ships to production;
// the hand-coded model in integration_helpers_test.go remains for legacy
// client_integration_test.go coverage only.
func loadModelFromDSL(t *testing.T, ctx context.Context, baseURL, storeID string) string {
	t.Helper()

	// Locate model.fga relative to the test package (which runs in this
	// authz/ directory).
	dslPath := "model.fga"
	if _, err := os.Stat(dslPath); err != nil {
		// Fallback for test runners that set CWD elsewhere.
		dslPath = filepath.Join("internal", "authz", "model.fga")
	}
	data, err := os.ReadFile(dslPath)
	require.NoError(t, err, "read model.fga")

	// Transform DSL → openfga-api proto model, then serialize to JSON with
	// protojson (canonical camelCase). The go-sdk's TypeDefinition struct
	// unmarshals that JSON shape directly.
	protoModel, err := transformer.TransformDSLToProto(string(data))
	require.NoError(t, err, "transform DSL to proto")

	jsonBytes, err := protojson.Marshal(protoModel)
	require.NoError(t, err, "marshal proto model")

	var payload struct {
		SchemaVersion   string                  `json:"schema_version"`
		TypeDefinitions []fgasdk.TypeDefinition `json:"type_definitions"`
	}
	require.NoError(t, json.Unmarshal(jsonBytes, &payload), "unmarshal into SDK types")

	c, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:  baseURL,
		StoreId: storeID,
	})
	require.NoError(t, err)

	resp, err := c.WriteAuthorizationModel(ctx).Body(fgaclient.ClientWriteAuthorizationModelRequest{
		SchemaVersion:   payload.SchemaVersion,
		TypeDefinitions: payload.TypeDefinitions,
	}).Execute()
	require.NoError(t, err, "WriteAuthorizationModel")

	return resp.GetAuthorizationModelId()
}
