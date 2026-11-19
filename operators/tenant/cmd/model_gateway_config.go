// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/modelprovider"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/outsideagent"
)

// The model gateway variables (gibson#1387). The model gateway is a required
// component, so the operator does not start without them.
const (
	// envModelGatewayNamespace is the dedicated namespace of the gateway. The
	// operator writes the backends, the routes and the credential Secrets
	// there, with a namespaced Role. It needs no cluster-wide write.
	envModelGatewayNamespace = "GIBSON_MODEL_GATEWAY_NAMESPACE"
	// envModelGatewayName is the name of the Gateway that the routes attach to.
	envModelGatewayName = "GIBSON_MODEL_GATEWAY_NAME"
)

// modelGatewayConfigFromEnv reads the render configuration of the model gateway.
// It names each missing variable.
func modelGatewayConfigFromEnv(getenv func(string) string) (modelprovider.Config, error) {
	var missing []string
	read := func(name string) string {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}
	cfg := modelprovider.Config{
		Namespace:   read(envModelGatewayNamespace),
		GatewayName: read(envModelGatewayName),
	}
	if len(missing) > 0 {
		return modelprovider.Config{}, fmt.Errorf("the model gateway is a required component, and %s must be set",
			strings.Join(missing, ", "))
	}
	return cfg, nil
}

// envAgentGatewayName is the name of the Gateway with the Agent listener
// (gibson#1403). The routes of the outside agents attach to it. The backends,
// the routes and the credential Secrets go in the namespace of
// GIBSON_MODEL_GATEWAY_NAMESPACE, which holds the whole gateway. The chart sets
// this name to the name of the model Gateway when one Gateway has both listeners.
const envAgentGatewayName = "GIBSON_AGENT_GATEWAY_NAME"

// agentGatewayConfigFromEnv reads the render configuration of the outside agents.
// It names each missing variable.
func agentGatewayConfigFromEnv(getenv func(string) string) (outsideagent.Config, error) {
	var missing []string
	read := func(name string) string {
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}
	cfg := outsideagent.Config{
		Namespace:   read(envModelGatewayNamespace),
		GatewayName: read(envAgentGatewayName),
	}
	if len(missing) > 0 {
		return outsideagent.Config{}, fmt.Errorf("the agent gateway is a required component, and %s must be set",
			strings.Join(missing, ", "))
	}
	return cfg, nil
}
