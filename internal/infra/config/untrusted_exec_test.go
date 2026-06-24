package config

import "testing"

func TestLoadUntrustedExec(t *testing.T) {
	cases := map[string]struct {
		want    string
		wantErr bool
	}{
		"":                       {"setec-only", false}, // unset ⇒ fail-closed
		"setec-only":             {"setec-only", false},
		"customer-isolation":     {"customer-isolation", false},
		"SETEC-ONLY":             {"setec-only", false},         // case-insensitive
		"  customer-isolation  ": {"customer-isolation", false}, // trimmed
		"nonsense":               {"", true},
	}
	for raw, tc := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("GIBSON_UNTRUSTED_EXEC", raw)
			got, err := loadUntrustedExec()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("loadUntrustedExec(%q) = %q, nil; want error", raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadUntrustedExec(%q) unexpected error: %v", raw, err)
			}
			if got != tc.want {
				t.Errorf("loadUntrustedExec(%q) = %q; want %q", raw, got, tc.want)
			}
		})
	}
}

// TestUntrustedExecModeFailClosed pins that an unwired Config (empty field)
// reports the strict mode.
func TestUntrustedExecModeFailClosed(t *testing.T) {
	var c Config
	if got := c.UntrustedExecMode(); got != "setec-only" {
		t.Fatalf("UntrustedExecMode() on zero Config = %q; want setec-only", got)
	}
	c.untrustedExec = "customer-isolation"
	if got := c.UntrustedExecMode(); got != "customer-isolation" {
		t.Fatalf("UntrustedExecMode() = %q; want customer-isolation", got)
	}
}
