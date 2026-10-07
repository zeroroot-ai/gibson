// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ciliumegress

import (
	"errors"
	"testing"
)

// An entry is host or host:port. The port is 443 when the entry names none.
// A bad host or a bad port is refused.
func TestParseEntry(t *testing.T) {
	cases := []struct {
		entry string
		host  string
		port  int
		bad   bool
	}{
		{entry: "api.github.com:443", host: "api.github.com", port: 443},
		{entry: "api.osv.dev", host: "api.osv.dev", port: 443},
		{entry: " *.slack.com:8443 ", host: "*.slack.com", port: 8443},
		{entry: "", bad: true},
		{entry: ":443", bad: true},
		{entry: "host:0", bad: true},
		{entry: "host:70000", bad: true},
		{entry: "host:abc", bad: true},
		{entry: "http://host", bad: true},
	}
	for _, want := range cases {
		entry := want.entry
		host, port, err := ParseEntry(entry)
		if want.bad {
			if !errors.Is(err, ErrBadEntry) {
				t.Errorf("ParseEntry(%q) err = %v, want ErrBadEntry", entry, err)
			}
			continue
		}
		if err != nil || host != want.host || port != want.port {
			t.Errorf("ParseEntry(%q) = %q, %d, %v; want %q, %d", entry, host, port, err, want.host, want.port)
		}
	}
}

// The first rule permits DNS, and each entry adds one TCP rule. A host with
// a star is a pattern, and a bad entry refuses the whole list.
func TestRules(t *testing.T) {
	rules, err := Rules([]string{"api.github.com:443", "*.slack.com"})
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("len(rules) = %d, want the DNS rule and two hosts", len(rules))
	}
	dns := rules[0].(map[string]interface{})
	if _, ok := dns["toEndpoints"]; !ok {
		t.Errorf("the first rule must permit DNS to kube-dns: %v", dns)
	}
	named := rules[1].(map[string]interface{})["toFQDNs"].([]interface{})[0].(map[string]interface{})
	if named["matchName"] != "api.github.com" {
		t.Errorf("a plain host must match by name: %v", named)
	}
	pattern := rules[2].(map[string]interface{})["toFQDNs"].([]interface{})[0].(map[string]interface{})
	if pattern["matchPattern"] != "*.slack.com" {
		t.Errorf("a host with a star must match by pattern: %v", pattern)
	}
	ports := rules[2].(map[string]interface{})["toPorts"].([]interface{})[0].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})
	if ports["port"] != "443" || ports["protocol"] != "TCP" {
		t.Errorf("the port of an entry with none must be 443/TCP: %v", ports)
	}
	if _, err := Rules([]string{"ok.example", "bad:port"}); !errors.Is(err, ErrBadEntry) {
		t.Errorf("a bad entry must refuse the list: %v", err)
	}
}

// NewPolicy is an empty CiliumNetworkPolicy.
func TestNewPolicy(t *testing.T) {
	u := NewPolicy()
	if u.GetAPIVersion() != APIVersion || u.GetKind() != Kind {
		t.Fatalf("NewPolicy = %s/%s", u.GetAPIVersion(), u.GetKind())
	}
}
