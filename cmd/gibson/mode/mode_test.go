package mode

import (
	"testing"
)

func TestGetMode_StandaloneCommands(t *testing.T) {
	tests := []struct {
		name    string
		cmdPath string
		want    CommandMode
	}{
		{
			name:    "version command",
			cmdPath: "gibson version",
			want:    Standalone,
		},
		{
			name:    "help command",
			cmdPath: "gibson help",
			want:    Standalone,
		},
		{
			name:    "config show command",
			cmdPath: "gibson config show",
			want:    Standalone,
		},
		{
			name:    "config get command",
			cmdPath: "gibson config get",
			want:    Standalone,
		},
		{
			name:    "config set command",
			cmdPath: "gibson config set",
			want:    Standalone,
		},
		{
			name:    "config validate command",
			cmdPath: "gibson config validate",
			want:    Standalone,
		},
		{
			name:    "completion bash command",
			cmdPath: "gibson completion bash",
			want:    Standalone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMode(tt.cmdPath)
			if got != tt.want {
				t.Errorf("GetMode(%q) = %v, want %v", tt.cmdPath, got, tt.want)
			}
		})
	}
}

func TestGetMode_DaemonCommands(t *testing.T) {
	tests := []struct {
		name    string
		cmdPath string
		want    CommandMode
	}{
		{
			name:    "daemon start command",
			cmdPath: "gibson daemon start",
			want:    Daemon,
		},
		{
			name:    "daemon stop command",
			cmdPath: "gibson daemon stop",
			want:    Daemon,
		},
		{
			name:    "daemon status command",
			cmdPath: "gibson daemon status",
			want:    Daemon,
		},
		{
			name:    "daemon restart command",
			cmdPath: "gibson daemon restart",
			want:    Daemon,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMode(tt.cmdPath)
			if got != tt.want {
				t.Errorf("GetMode(%q) = %v, want %v", tt.cmdPath, got, tt.want)
			}
		})
	}
}

func TestGetMode_ClientCommands(t *testing.T) {
	tests := []struct {
		name    string
		cmdPath string
		want    CommandMode
	}{
		{
			name:    "root command",
			cmdPath: "gibson",
			want:    Client,
		},
		{
			name:    "tui command",
			cmdPath: "gibson tui",
			want:    Client,
		},
		{
			name:    "attack command",
			cmdPath: "gibson attack",
			want:    Client,
		},
		{
			name:    "mission run command",
			cmdPath: "gibson mission run",
			want:    Client,
		},
		{
			name:    "mission list command",
			cmdPath: "gibson mission list",
			want:    Client,
		},
		{
			name:    "agent list command",
			cmdPath: "gibson agent list",
			want:    Client,
		},
		{
			name:    "agent install command",
			cmdPath: "gibson agent install",
			want:    Client,
		},
		{
			name:    "agent start command",
			cmdPath: "gibson agent start",
			want:    Client,
		},
		{
			name:    "tool list command",
			cmdPath: "gibson tool list",
			want:    Client,
		},
		{
			name:    "tool invoke command",
			cmdPath: "gibson tool invoke",
			want:    Client,
		},
		{
			name:    "plugin list command",
			cmdPath: "gibson plugin list",
			want:    Client,
		},
		{
			name:    "finding list command",
			cmdPath: "gibson finding list",
			want:    Client,
		},
		{
			name:    "target list command",
			cmdPath: "gibson target list",
			want:    Client,
		},
		{
			name:    "credential list command",
			cmdPath: "gibson credential list",
			want:    Client,
		},
		{
			name:    "payload list command",
			cmdPath: "gibson payload list",
			want:    Client,
		},
		{
			name:    "payload chain execute command",
			cmdPath: "gibson payload chain execute",
			want:    Client,
		},
		{
			name:    "status command",
			cmdPath: "gibson status",
			want:    Client,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMode(tt.cmdPath)
			if got != tt.want {
				t.Errorf("GetMode(%q) = %v, want %v", tt.cmdPath, got, tt.want)
			}
		})
	}
}

func TestGetMode_UnknownCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmdPath string
		want    CommandMode
	}{
		{
			name:    "unknown command returns Client",
			cmdPath: "gibson unknown",
			want:    Client,
		},
		{
			name:    "unknown subcommand returns Client",
			cmdPath: "gibson agent unknown-subcommand",
			want:    Client,
		},
		{
			name:    "empty path returns Client",
			cmdPath: "",
			want:    Client,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetMode(tt.cmdPath)
			if got != tt.want {
				t.Errorf("GetMode(%q) = %v, want %v", tt.cmdPath, got, tt.want)
			}
		})
	}
}

func TestCommandMode_String(t *testing.T) {
	tests := []struct {
		name string
		mode CommandMode
		want string
	}{
		{
			name: "Standalone string",
			mode: Standalone,
			want: "Standalone",
		},
		{
			name: "Daemon string",
			mode: Daemon,
			want: "Daemon",
		},
		{
			name: "Client string",
			mode: Client,
			want: "Client",
		},
		{
			name: "Unknown mode",
			mode: CommandMode(999),
			want: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("CommandMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	// Save original registry
	original := make(map[string]CommandMode)
	for k, v := range CommandRegistry {
		original[k] = v
	}

	// Restore after test
	defer func() {
		CommandRegistry = original
	}()

	// Test registering a new command
	testPath := "gibson test newcommand"
	Register(testPath, Standalone)

	got := GetMode(testPath)
	if got != Standalone {
		t.Errorf("After Register(%q, Standalone), GetMode() = %v, want Standalone", testPath, got)
	}

	// Test overwriting an existing command
	Register(testPath, Client)
	got = GetMode(testPath)
	if got != Client {
		t.Errorf("After Register(%q, Client), GetMode() = %v, want Client", testPath, got)
	}
}
