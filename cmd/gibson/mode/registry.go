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

	// Daemon commands - Manages daemon lifecycle
	Register("gibson daemon", Daemon)
	Register("gibson daemon start", Daemon)
	Register("gibson daemon stop", Daemon)
	Register("gibson daemon status", Daemon)
	Register("gibson daemon restart", Daemon)

	// Client commands - Require daemon connection
	Register("gibson", Client) // Root command (shows help)
	Register("gibson status", Client)
	Register("gibson attack", Client)

	// Mission commands
	Register("gibson mission", Client)
	Register("gibson mission list", Client)
	Register("gibson mission show", Client)
	Register("gibson mission run", Client)
	Register("gibson mission resume", Client)
	Register("gibson mission stop", Client)
	Register("gibson mission delete", Client)

	// Agent commands
	Register("gibson agent", Client)
	Register("gibson agent list", Client)
	Register("gibson agent install", Client)
	Register("gibson agent install-all", Client)
	Register("gibson agent uninstall", Client)
	Register("gibson agent update", Client)
	Register("gibson agent show", Client)
	Register("gibson agent build", Client)
	Register("gibson agent start", Client)
	Register("gibson agent stop", Client)
	Register("gibson agent status", Client)
	Register("gibson agent logs", Client)

	// Tool commands
	Register("gibson tool", Client)
	Register("gibson tool list", Client)
	Register("gibson tool install", Client)
	Register("gibson tool install-all", Client)
	Register("gibson tool uninstall", Client)
	Register("gibson tool update", Client)
	Register("gibson tool show", Client)
	Register("gibson tool build", Client)
	Register("gibson tool start", Client)
	Register("gibson tool stop", Client)
	Register("gibson tool status", Client)
	Register("gibson tool logs", Client)
	Register("gibson tool test", Client)
	Register("gibson tool invoke", Client)

	// Plugin commands
	Register("gibson plugin", Client)
	Register("gibson plugin list", Client)
	Register("gibson plugin install", Client)
	Register("gibson plugin install-all", Client)
	Register("gibson plugin uninstall", Client)
	Register("gibson plugin update", Client)
	Register("gibson plugin show", Client)
	Register("gibson plugin build", Client)
	Register("gibson plugin start", Client)
	Register("gibson plugin stop", Client)
	Register("gibson plugin status", Client)
	Register("gibson plugin logs", Client)
	Register("gibson plugin query", Client)

	// Finding commands
	Register("gibson finding", Client)
	Register("gibson finding list", Client)
	Register("gibson finding show", Client)
	Register("gibson finding export", Client)

	// Target commands
	Register("gibson target", Client)
	Register("gibson target list", Client)
	Register("gibson target add", Client)
	Register("gibson target show", Client)
	Register("gibson target test", Client)
	Register("gibson target delete", Client)

	// Credential commands
	Register("gibson credential", Client)
	Register("gibson credential list", Client)
	Register("gibson credential add", Client)
	Register("gibson credential show", Client)
	Register("gibson credential test", Client)
	Register("gibson credential rotate", Client)
	Register("gibson credential delete", Client)

	// Payload commands
	Register("gibson payload", Client)
	Register("gibson payload list", Client)
	Register("gibson payload show", Client)
	Register("gibson payload create", Client)
	Register("gibson payload execute", Client)
	Register("gibson payload chain", Client)
	Register("gibson payload chain list", Client)
	Register("gibson payload chain show", Client)
	Register("gibson payload chain create", Client)
	Register("gibson payload chain execute", Client)
	Register("gibson payload stats", Client)
	Register("gibson payload import", Client)
	Register("gibson payload export", Client)
	Register("gibson payload search", Client)
}
