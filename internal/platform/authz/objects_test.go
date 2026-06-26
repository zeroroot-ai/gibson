package authz

import "testing"

func TestComponentObject(t *testing.T) {
	if got := ComponentObject("nmap"); got != "component:nmap" {
		t.Fatalf("ComponentObject(nmap) = %q", got)
	}
}

func TestPluginObject(t *testing.T) {
	if got := PluginObject("acme", "gitlab"); got != "plugin:acme/gitlab" {
		t.Fatalf("PluginObject(acme, gitlab) = %q", got)
	}
}

func TestCanonicalComponentResource(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		want     string
	}{
		{"bare name", "nmap", "component:nmap"},
		{"kind tool", "tool:nmap", "component:nmap"},
		{"kind agent", "agent:scan-controller", "component:scan-controller"},
		{"kind plugin two-segment", "plugin:gitlab", "component:gitlab"},
		{"already canonical", "component:nmap", "component:nmap"},
		{"legacy kind-qualified object", "component:tool:nmap", "component:nmap"},
		{"legacy kind-qualified object plugin", "component:plugin:gitlab", "component:gitlab"},
		{"typed plugin object (colon-free) untouched", "plugin:acme/gitlab", "plugin:acme/gitlab"},
		{"legacy colon typed plugin object untouched", "plugin:acme:gitlab", "plugin:acme:gitlab"},
		{"other typed ref untouched", "mission:abc-123", "mission:abc-123"},
		{"hyphenated name", "nmap-agent", "component:nmap-agent"},
		{"component name with hyphen and kind", "tool:web-scanner", "component:web-scanner"},
		{"three-segment non-component untouched", "team:acme:ops", "team:acme:ops"},
		{"component with non-kind middle untouched", "component:acme:thing", "component:acme:thing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalComponentResource(tc.resource); got != tc.want {
				t.Fatalf("CanonicalComponentResource(%q) = %q, want %q", tc.resource, got, tc.want)
			}
		})
	}
}
