package client

import "os"

// EnvDaemonToken is the environment variable for daemon authentication token.
//
// When set, the CLI client will use this token for bearer token authentication
// with remote daemons. This is particularly useful for connecting to daemons
// running in Kubernetes via port-forwarding where trust_localhost doesn't apply.
//
// The token is sent as "Authorization: Bearer <token>" in gRPC metadata.
//
// Example:
//
//	export GIBSON_DAEMON_TOKEN=gibson-admin-token
//	gibson mission run workflow.yaml
const EnvDaemonToken = "GIBSON_DAEMON_TOKEN"

// TokenSource represents where a token was resolved from.
//
// The token resolution follows a precedence order:
//  1. CLI flag (--daemon-token)
//  2. Environment variable (GIBSON_DAEMON_TOKEN)
//  3. Config file (daemon.token)
//  4. None (no authentication)
type TokenSource string

const (
	// TokenSourceNone indicates no token was provided
	TokenSourceNone TokenSource = "none"

	// TokenSourceFlag indicates the token came from a CLI flag
	TokenSourceFlag TokenSource = "flag"

	// TokenSourceEnv indicates the token came from an environment variable
	TokenSourceEnv TokenSource = "env"

	// TokenSourceConfig indicates the token came from the config file
	TokenSourceConfig TokenSource = "config"
)

// TokenOptions contains options for token resolution.
//
// This struct is used to pass token values from different sources to the
// ResolveToken function, which determines which token to use based on
// precedence rules.
type TokenOptions struct {
	// FlagToken is a token provided via CLI flag (highest priority)
	// Example: --daemon-token <token>
	FlagToken string

	// ConfigToken is a token from config file (lowest priority)
	// Example: daemon.token in ~/.gibson/config.yaml
	ConfigToken string
}

// ResolveToken determines the token to use based on precedence.
//
// Token resolution follows this precedence order (highest to lowest):
//  1. CLI flag (TokenOptions.FlagToken)
//  2. Environment variable (GIBSON_DAEMON_TOKEN)
//  3. Config file (TokenOptions.ConfigToken)
//  4. None (empty token)
//
// An empty token is valid and indicates no authentication should be used,
// which is appropriate for local daemon connections with trust_localhost enabled.
//
// Parameters:
//   - opts: TokenOptions containing flag and config token values
//
// Returns:
//   - token: The resolved token string (may be empty)
//   - source: Where the token came from (for logging/debugging)
//
// Example:
//
//	opts := TokenOptions{
//	    FlagToken:   cmd.Flag("daemon-token").Value.String(),
//	    ConfigToken: cfg.Daemon.Token,
//	}
//	token, source := ResolveToken(opts)
//	if token != "" {
//	    log.Printf("Using daemon token from %s", source)
//	}
func ResolveToken(opts TokenOptions) (token string, source TokenSource) {
	// 1. CLI flag (highest priority)
	if opts.FlagToken != "" {
		return opts.FlagToken, TokenSourceFlag
	}

	// 2. Environment variable
	if envToken := os.Getenv(EnvDaemonToken); envToken != "" {
		return envToken, TokenSourceEnv
	}

	// 3. Config file (lowest priority)
	if opts.ConfigToken != "" {
		return opts.ConfigToken, TokenSourceConfig
	}

	// 4. No token
	return "", TokenSourceNone
}
