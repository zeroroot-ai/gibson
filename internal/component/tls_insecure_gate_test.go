package component

import (
	"strings"
	"testing"
)

// Regression for gibson#545: InsecureSkipVerify must fail-closed unless the
// explicit AllowInsecureSkipVerify dev opt-in is also set.
func TestBuildTLSConfig_InsecureSkipVerifyFailsClosed(t *testing.T) {
	c := &TLSConfig{Enabled: true, InsecureSkipVerify: true}
	_, err := c.BuildTLSConfig()
	if err == nil {
		t.Fatal("expected error when InsecureSkipVerify=true without AllowInsecureSkipVerify")
	}
	if !strings.Contains(err.Error(), "AllowInsecureSkipVerify") {
		t.Fatalf("error should name the required opt-in, got: %v", err)
	}
}

func TestBuildTLSConfig_InsecureSkipVerifyExplicitOptIn(t *testing.T) {
	c := &TLSConfig{Enabled: true, InsecureSkipVerify: true, AllowInsecureSkipVerify: true}
	cfg, err := c.BuildTLSConfig()
	if err != nil {
		t.Fatalf("explicit opt-in should be honored, got: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be set on the tls.Config with the opt-in")
	}
}

func TestBuildTLSConfig_SecureByDefault(t *testing.T) {
	c := &TLSConfig{Enabled: true, ServerName: "daemon.example"}
	cfg, err := c.BuildTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("verification must be ON by default")
	}
}
