// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/modelprovider"
)

// The model gateway variables (gibson#1387). The model gateway is a required
// component, so the operator does not start without them.
const (
	// envModelGatewayNamespace is the namespace of the gateway. The operator
	// writes the backends and the routes there, and it reads the credential
	// Secrets there.
	envModelGatewayNamespace = "GIBSON_MODEL_GATEWAY_NAMESPACE"
	// envModelGatewayName is the name of the Gateway that the routes attach to.
	envModelGatewayName = "GIBSON_MODEL_GATEWAY_NAME"
	// envModelGatewayExtAuthzService is the name of the ext-authz Service.
	envModelGatewayExtAuthzService = "GIBSON_MODEL_GATEWAY_EXTAUTHZ_SERVICE"
	// envModelGatewayExtAuthzNamespace is the namespace of that Service. It
	// defaults to the namespace of the gateway.
	envModelGatewayExtAuthzNamespace = "GIBSON_MODEL_GATEWAY_EXTAUTHZ_NAMESPACE"
	// envModelGatewayExtAuthzPort is the gRPC port of that Service.
	envModelGatewayExtAuthzPort = "GIBSON_MODEL_GATEWAY_EXTAUTHZ_PORT"
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
		Namespace:         read(envModelGatewayNamespace),
		GatewayName:       read(envModelGatewayName),
		ExtAuthzName:      read(envModelGatewayExtAuthzService),
		ExtAuthzNamespace: strings.TrimSpace(getenv(envModelGatewayExtAuthzNamespace)),
	}
	portText := read(envModelGatewayExtAuthzPort)
	if len(missing) > 0 {
		return modelprovider.Config{}, fmt.Errorf("the model gateway is a required component, and %s must be set",
			strings.Join(missing, ", "))
	}
	port, err := strconv.ParseInt(portText, 10, 32)
	if err != nil || port <= 0 || port > 65535 {
		return modelprovider.Config{}, errors.New(envModelGatewayExtAuthzPort + " must be a port number")
	}
	cfg.ExtAuthzPort = int32(port)
	return cfg, nil
}
