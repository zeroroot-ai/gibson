// Package secretslogviolation is a synthetic test fixture for the
// secretsnolog gibsoncheck rule (platform-clients surface). It deliberately
// passes the return value of a secrets Get/Resolve call to several logging
// sinks so that the analyzer fires a diagnostic on each flagged line.
package secretslogviolation

import (
	"context"
	"fmt"
	"log"
	"log/slog"

	"github.com/zero-day-ai/platform-clients/secrets"
)

// violateDirect calls broker.Get and passes the result directly to slog.Info.
func violateDirect(ctx context.Context, broker secrets.SecretsBroker) {
	value, _ := broker.Get(ctx, "tenant1", "cred:db_password")
	slog.Info("got secret", "value", value) // want "secrets value from Get/Resolve must not be passed to a logging sink"
}

// violateRename calls broker.Get, assigns to a local variable, then logs it.
func violateRename(ctx context.Context, broker secrets.SecretsBroker) {
	plaintext, _ := broker.Get(ctx, "tenant1", "cred:api_key")
	log.Println(plaintext) // want "secrets value from Get/Resolve must not be passed to a logging sink"
}

// violateResolve calls Service.Resolve and passes the result to fmt.Printf.
func violateResolve(ctx context.Context, svc *secrets.Service) {
	data, _ := svc.Resolve(ctx, "provider_config:anthropic:default")
	fmt.Printf("resolved: %s\n", data) // want "secrets value from Get/Resolve must not be passed to a logging sink"
}

// violateSlog calls broker.Get and logs via slog.Error.
func violateSlog(ctx context.Context, broker secrets.SecretsBroker) {
	val, _ := broker.Get(ctx, "tenant1", "cred:token")
	slog.Error("secret value", "raw", val) // want "secrets value from Get/Resolve must not be passed to a logging sink"
}
