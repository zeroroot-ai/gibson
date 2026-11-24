// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ciliumegress

import (
	"errors"
	"net"
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

// The deny rule holds each private, link-local, loopback, CGNAT and unique
// local range, and the cluster ranges. A bad cluster range refuses the rule.
// The metadata address and a rebinding answer in 10/8 fall in the denied set.
func TestDenyRules(t *testing.T) {
	rules, err := DenyRules([]string{"10.244.0.0/16", "fd00:10:96::/112"})
	if err != nil {
		t.Fatalf("DenyRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want one deny rule", rules)
	}
	set := rules[0].(map[string]interface{})["toCIDRSet"].([]interface{})
	nets := make([]*net.IPNet, 0, len(set))
	got := map[string]bool{}
	for _, e := range set {
		c := e.(map[string]interface{})["cidr"].(string)
		got[c] = true
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		nets = append(nets, n)
	}
	for _, want := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
		"100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128", "10.244.0.0/16", "fd00:10:96::/112",
	} {
		if !got[want] {
			t.Errorf("the deny rule has no %s: %v", want, set)
		}
	}
	for _, ip := range []string{"169.254.169.254", "10.1.2.3", "172.20.0.1", "192.168.1.1", "100.100.0.1", "127.0.0.1", "::1", "fe80::1", "fd12::1"} {
		denied := false
		for _, n := range nets {
			if n.Contains(net.ParseIP(ip)) {
				denied = true
			}
		}
		if !denied {
			t.Errorf("%s is not denied", ip)
		}
	}
	for _, ip := range []string{"140.82.112.6", "2606:50c0:8000::153"} {
		for _, n := range nets {
			if n.Contains(net.ParseIP(ip)) {
				t.Errorf("the public address %s is denied by %s", ip, n)
			}
		}
	}
	if _, err := DenyRules([]string{"10.244.0.0"}); !errors.Is(err, ErrBadCIDR) {
		t.Errorf("a bad cluster range: err = %v, want ErrBadCIDR", err)
	}
}
