package fga

import (
	"fmt"

	fgaclient "github.com/openfga/go-sdk/client"
)

// ---- real OpenFGA client constructor ----------------------------------------

// NewOpenFGAClient creates a real *fgaclient.OpenFgaClient connected to the
// given FGA gRPC address and store ID.
//
// addr is the host:port of the OpenFGA gRPC API (e.g. "openfga:8081").
// storeID is the FGA store UUID.
func NewOpenFGAClient(addr, storeID string) (FGAClient, error) {
	if addr == "" {
		return nil, fmt.Errorf("fga.NewOpenFGAClient: addr must not be empty")
	}
	if storeID == "" {
		return nil, fmt.Errorf("fga.NewOpenFGAClient: storeID must not be empty")
	}

	cfg := fgaclient.ClientConfiguration{
		ApiUrl:  "http://" + addr,
		StoreId: storeID,
	}

	client, err := fgaclient.NewSdkClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("fga.NewOpenFGAClient: %w", err)
	}
	return client, nil
}

// Ensure *fgaclient.OpenFgaClient satisfies FGAClient at compile time.
// The method set of *fgaclient.OpenFgaClient is checked by the compiler when
// this file is compiled alongside check.go where FGAClient is defined.
var _ FGAClient = (*fgaclient.OpenFgaClient)(nil)
