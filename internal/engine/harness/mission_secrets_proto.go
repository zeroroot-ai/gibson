// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// MissionSecretScopesFromProto reads a mission definition's secrets block into
// the value this package resolves against.
//
// Translated once, where the caller already holds the definition, so the rest of
// the harness never carries a proto message it would have to nil-check at every
// read. A nil block yields the zero value, which hands nothing to anything —
// the behaviour before a mission could declare secrets.
//
// No name is validated here. A name that does not resolve is a dispatch-time
// refusal with the component and the name in the message, which is where an
// operator can act on it. Refusing at projection would fail the whole mission
// for a secret that may belong to a node this run never reaches.
func MissionSecretScopesFromProto(in *missionv1.MissionSecrets) MissionSecretScopes {
	if in == nil {
		return MissionSecretScopes{}
	}
	return MissionSecretScopes{
		Mission: in.GetMission(),
		Agents:  in.GetAgents(),
		Tools:   in.GetTools(),
		Plugins: in.GetPlugins(),
		Agent:   namedSecrets(in.GetAgent()),
		Tool:    namedSecrets(in.GetTool()),
		Plugin:  namedSecrets(in.GetPlugin()),
	}
}

// namedSecrets unwraps the per-component map. proto3 has no repeated map value,
// so each entry is a SecretNames message; the Go side carries plain slices
// because that is what the union reads.
//
// An entry whose message is nil is kept as an empty slice rather than dropped.
// The mission named the component, and Declares must not read as "declared
// nothing" for a mission that did.
func namedSecrets(in map[string]*missionv1.SecretNames) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for name, names := range in {
		out[name] = names.GetNames()
	}
	return out
}
