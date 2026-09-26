// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// signInPolicy is the sign-in policy of every install (ADR-0093 section 9):
// MFA for everyone, passkey or authenticator app only, no external IdPs, no
// self-service registration. It is code, not configuration — no chart value
// and no CRD field can turn MFA off, because a knob that can turn a security
// invariant off is a way to turn it off.
var signInPolicy = zitadel.LoginPolicy{
	AllowUsernamePassword: true,  // TOTP and U2F are second factors after a password.
	AllowRegister:         false, // deploy#886: all accounts come through the admin API.
	AllowExternalIDP:      false,
	ForceMFA:              true,
	ForceMFALocalOnly:     false, // false would exempt IdP sign-ins from MFA.
	PasswordlessAllowed:   true,  // allows passkeys.
	AllowDomainDiscovery:  false, // registration is off; this would only leak org domains.
	MFAInitSkipLifetime:   0,     // removes the "skip for now" choice.
	SecondFactors:         []string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_U2F"},
	MultiFactors:          []string{"MULTI_FACTOR_TYPE_U2F_WITH_VERIFICATION"},
}

// usernamePolicy keeps usernames (our usernames are the person's email
// address, see idp.UsernameForEmail) unique across the whole install, not
// just within one org (ADR-0093 decision 1).
var usernamePolicy = zitadel.DomainPolicy{UserLoginMustBeDomain: false}
