// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga/flows"
)

// envBeliefTrainerImage names the gibson image that the belief trainer
// CronJob of each tenant runs (gibson#616). The chart sets it to the pinned
// daemon image, which holds the belief-trainer binary.
const envBeliefTrainerImage = "BELIEF_TRAINER_IMAGE"

// beliefTrainerConfigFromEnv builds the trainer config. The trainer dials the
// same daemon as the operator, so it reuses the daemon address and SPIFFE ID
// of the operator. The daemon pods run in OPERATOR_NAMESPACE, as the
// namespace provisioner also assumes.
func beliefTrainerConfigFromEnv(getenv func(string) string) (flows.BeliefTrainerConfig, error) {
	cfg, err := flows.NewBeliefTrainerConfig(
		getenv(envBeliefTrainerImage),
		getenv(envDaemonGRPCAddress),
		getenv(envDaemonSPIFFEID),
		getenv("OPERATOR_NAMESPACE"),
	)
	if err != nil {
		return flows.BeliefTrainerConfig{}, fmt.Errorf("set %s, %s, %s and OPERATOR_NAMESPACE: %w",
			envBeliefTrainerImage, envDaemonGRPCAddress, envDaemonSPIFFEID, err)
	}
	return cfg, nil
}
