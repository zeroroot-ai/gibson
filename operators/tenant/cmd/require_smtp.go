/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package main

import "fmt"

// validateSMTPEnvKey is the one-code-path (tenant-operator#95) startup
// contract for the SMTP mail sender. The operator refuses to boot when
// SMTP_HOST is absent. The previous behaviour (NullSender default → email
// silently discarded) masked missing SMTP configuration as phantom delivery.
//
// The function is pure (takes a getenv functor) so the contract is testable
// without mutating process environment. main() wires it via os.Getenv.
func validateSMTPEnvKey(getenv func(string) string) error {
	if getenv("SMTP_HOST") == "" {
		return fmt.Errorf(
			"SMTP_HOST is required (one-code-path / tenant-operator#95): " +
				"the operator sends transactional email (welcome, invitations) via SMTP; " +
				"set SMTP_HOST to enable email delivery",
		)
	}
	return nil
}
