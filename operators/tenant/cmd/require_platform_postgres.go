/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import "fmt"

// requirePlatformPostgresMissingEnv is the name of the env var the gate
// inspects. Surfaced as a const so the contract test can pin it.
const requirePlatformPostgresMissingEnv = "DATAPLANE_PG_ADMIN_DSN"

// requirePlatformPostgres returns a structured error when the platform
// Postgres DSN is missing. one-code-path/198: the platform Postgres is
// structurally required, --dev-mode does NOT bypass this gate, and the
// only legal startup state is one where the gate returns nil.
//
// getenv is parameterised so the test can drive it without touching the
// process environment.
func requirePlatformPostgres(getenv func(string) string) error {
	if getenv(requirePlatformPostgresMissingEnv) == "" {
		return fmt.Errorf(
			"platform Postgres is required: %s is unset. "+
				"Set it to a reachable Postgres admin DSN "+
				"(kind: postgres://tenant_admin:<pw>@platform-postgres-rw.gibson.svc.cluster.local:5432/postgres?sslmode=disable; "+
				"eks: ESO-projected from RDS credentials). "+
				"--dev-mode does NOT bypass this gate. See one-code-path epic deploy#186 / deploy#198",
			requirePlatformPostgresMissingEnv,
		)
	}
	return nil
}
