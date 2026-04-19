package mode

func init() {
	// Standalone commands - No daemon required
	Register("gibson version", Standalone)
	Register("gibson help", Standalone)
	Register("gibson completion", Standalone)
	Register("gibson completion bash", Standalone)
	Register("gibson completion zsh", Standalone)
	Register("gibson completion fish", Standalone)
	Register("gibson completion powershell", Standalone)
	Register("gibson config", Standalone)
	Register("gibson config show", Standalone)
	Register("gibson config get", Standalone)
	Register("gibson config set", Standalone)
	Register("gibson config validate", Standalone)

	// Authz commands - Direct FGA interaction (standalone, no daemon needed)
	Register("gibson authz", Standalone)
	Register("gibson authz check", Standalone)
	Register("gibson authz write", Standalone)
	Register("gibson authz model-info", Standalone)

	// Migration commands - standalone (connects directly to daemon and k8s, not via registry)
	Register("gibson migrate-providers", Standalone)

	// Daemon commands - Manages daemon lifecycle
	Register("gibson daemon", Daemon)
	Register("gibson daemon start", Daemon)
	Register("gibson daemon stop", Daemon)
	Register("gibson daemon status", Daemon)
	Register("gibson daemon restart", Daemon)
}
