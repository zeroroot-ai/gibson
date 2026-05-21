// Package secretslogclean is a synthetic test fixture for the secretsnolog
// gibsoncheck rule (platform-clients surface). It calls secrets Get/Resolve
// but uses the returned bytes only for legitimate purposes — never passing
// them to a logging sink. The analyzer must emit zero diagnostics against
// this package.
package secretslogclean

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/platform-clients/secrets"
)

// legitimateHMAC computes an HMAC of a message using the secret as the key.
// The secret bytes are never logged.
func legitimateHMAC(ctx context.Context, broker secrets.SecretsBroker, message []byte) ([]byte, error) {
	key, err := broker.Get(ctx, "tenant1", "cred:hmac_key")
	if err != nil {
		return nil, fmt.Errorf("get hmac key: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

// legitimateLength logs the length of the secret (not the value itself).
func legitimateLength(ctx context.Context, svc *secrets.Service) {
	value, err := svc.Resolve(ctx, "cred:tls_cert")
	if err != nil {
		slog.Error("failed to resolve secret", "err", err)
		return
	}
	// Log the length only — never the value. This must NOT trigger.
	slog.Info("secret resolved", "bytes", len(value))
}

// legitimateReturn returns the secret value to its caller without logging.
func legitimateReturn(ctx context.Context, broker secrets.SecretsBroker) ([]byte, error) {
	return broker.Get(ctx, "tenant1", "cred:signing_key")
}
