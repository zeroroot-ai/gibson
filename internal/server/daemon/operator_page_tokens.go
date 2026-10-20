// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/crypto"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// wireOperatorPageTokens gives the DaemonOperatorService the keys that sign the
// page tokens of its list RPCs. The keys come from the master KEK, which every
// daemon replica shares, so a token from one replica works on another
// (ADR-0028, gibson#1261). A daemon with no key provider does not start,
// because an unsigned page token is never an option.
func wireOperatorPageTokens(ctx context.Context, svc *api.DaemonServer, kp crypto.KeyProvider) error {
	if kp == nil {
		return errors.New("daemon: DaemonOperatorService needs the key provider to sign page tokens")
	}
	masterKEK, err := kp.GetEncryptionKey(ctx)
	if err != nil {
		return fmt.Errorf("daemon: DaemonOperatorService could not read the master KEK: %w", err)
	}
	if _, err := svc.WithPageTokenKEK(masterKEK); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	return nil
}
