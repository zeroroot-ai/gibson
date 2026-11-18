// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"fmt"
	"os"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// EnvModelGatewayURL names the environment variable that holds the URL of the
// model gateway. The daemon sends each model call there (gibson#1392).
const EnvModelGatewayURL = "GIBSON_MODEL_GATEWAY_URL"

// lazyDaemonMinter signs with the Minter of the daemon. The Minter is built
// later in Start than the clients that need it, so each call reads it.
type lazyDaemonMinter struct{ d *daemonImpl }

func (l lazyDaemonMinter) Mint(req capabilitygrant.MintRequest) (string, error) {
	if l.d.cgMinter == nil {
		return "", errUnavailable("the daemon has no signing key, so it cannot sign the grant of a model call")
	}
	tok, err := l.d.cgMinter.Mint(req)
	if err != nil {
		return "", fmt.Errorf("sign the grant of a model call: %w", err)
	}
	return tok, nil
}

// newModelClient builds the model client of the daemon. The gateway URL is
// required: the daemon calls no model provider, so without the gateway it has no
// model.
func (d *daemonImpl) newModelClient() (*modelclient.Client, error) {
	url := strings.TrimSpace(os.Getenv(EnvModelGatewayURL))
	if url == "" {
		return nil, fmt.Errorf("%s is not set: the daemon sends each model call to the model gateway", EnvModelGatewayURL)
	}
	grants, err := modelclient.NewMinterGrants(lazyDaemonMinter{d})
	if err != nil {
		return nil, fmt.Errorf("model client grants: %w", err)
	}
	c, err := modelclient.New(modelclient.Config{BaseURL: url, Grants: grants})
	if err != nil {
		return nil, fmt.Errorf("model client: %w", err)
	}
	return c, nil
}
