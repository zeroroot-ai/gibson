// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient/mintgrants"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
)

// EnvModelGatewayURL names the environment variable that holds the URL of the
// model gateway. The daemon sends each model call there (gibson#1392).
const EnvModelGatewayURL = "GIBSON_MODEL_GATEWAY_URL"

// EnvModelGatewayCAFile names the environment variable that holds the path of
// the CA bundle (PEM) that signs the TLS certificate of the model gateway. It is
// the component CA. The daemon trusts only this bundle for the gateway.
const EnvModelGatewayCAFile = "GIBSON_MODEL_GATEWAY_CA_FILE"

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

func (l lazyDaemonMinter) MintDaemonCall(req capabilitygrant.DaemonCallRequest) (string, error) {
	if l.d.cgMinter == nil {
		return "", errUnavailable("the daemon has no signing key, so it cannot sign the grant of a model call")
	}
	tok, err := l.d.cgMinter.MintDaemonCall(req)
	if err != nil {
		return "", fmt.Errorf("sign the daemon call grant: %w", err)
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
	httpClient, err := modelGatewayHTTPClient(os.Getenv(EnvModelGatewayCAFile))
	if err != nil {
		return nil, err
	}
	grants, err := mintgrants.New(lazyDaemonMinter{d})
	if err != nil {
		return nil, fmt.Errorf("model client grants: %w", err)
	}
	c, err := modelclient.New(modelclient.Config{BaseURL: url, Grants: grants, HTTPClient: httpClient})
	if err != nil {
		return nil, fmt.Errorf("model client: %w", err)
	}
	return c, nil
}

// modelGatewayHTTPClient returns an HTTP client that trusts the CA bundle in the
// file, and no other CA, for the TLS certificate of the model gateway. The
// client has no overall timeout, so a stream can run. The caller sets a deadline
// on the context.
func modelGatewayHTTPClient(caFile string) (*http.Client, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return nil, fmt.Errorf("%s is not set: the model gateway serves TLS with the component CA", EnvModelGatewayCAFile)
	}
	pemBytes, err := os.ReadFile(caFile) //nolint:gosec // G304: the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", EnvModelGatewayCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificate", EnvModelGatewayCAFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr}, nil
}

// The public URLs of the gateways, for an agent in a sandbox. A sandbox reaches
// the cluster only through the Edge, never through an in-cluster service name.
// The daemon keeps GIBSON_MODEL_GATEWAY_URL for its own model client.
const (
	// EnvModelGatewayPublicURL is the public URL of the model gateway: the
	// Edge route /gateway/model/.
	EnvModelGatewayPublicURL = "GIBSON_MODEL_GATEWAY_PUBLIC_URL"
	// EnvAgentGatewayPublicURL is the public URL of the agent gateway: the Edge
	// route /gateway/agent/.
	EnvAgentGatewayPublicURL = "GIBSON_AGENT_GATEWAY_PUBLIC_URL"
	// EnvGatewayPublicCAFile is the optional PEM CA bundle that signs the public
	// certificate. Unset means a public CA, and the reply holds no bundle.
	EnvGatewayPublicCAFile = "GIBSON_GATEWAY_PUBLIC_CA_FILE"
)

// publicGatewayInfo reads one public gateway URL and the optional public CA.
func publicGatewayInfo(urlEnv string) (harness.GatewayInfo, error) {
	url := strings.TrimSpace(os.Getenv(urlEnv))
	if url == "" {
		return harness.GatewayInfo{}, fmt.Errorf("%s is not set", urlEnv)
	}
	info := harness.GatewayInfo{URL: url}
	if caFile := strings.TrimSpace(os.Getenv(EnvGatewayPublicCAFile)); caFile != "" {
		pemBytes, err := os.ReadFile(caFile) //nolint:gosec // G304: the path is operator configuration
		if err != nil {
			return harness.GatewayInfo{}, fmt.Errorf("read %s: %w", EnvGatewayPublicCAFile, err)
		}
		info.CAPEM = string(pemBytes)
	}
	return info, nil
}

// modelGatewayInfoFromEnv reads what an SDK agent needs to reach the model
// gateway: the PUBLIC URL and, when a private CA signs it, the PEM bundle.
// ResolveModel returns it (the RPC handlers wait for the SDK module that has the
// RPC).
func modelGatewayInfoFromEnv() (harness.GatewayInfo, error) {
	return publicGatewayInfo(EnvModelGatewayPublicURL)
}

// agentGatewayInfoFromEnv reads what an SDK agent needs to reach the agent
// gateway. ResolveAgent returns it.
func agentGatewayInfoFromEnv() (harness.GatewayInfo, error) {
	return publicGatewayInfo(EnvAgentGatewayPublicURL)
}
