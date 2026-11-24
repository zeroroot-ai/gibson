// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"strings"
	"testing"
)

func TestCredentialHeader_Value(t *testing.T) {
	cases := map[string]struct {
		h      CredentialHeader
		secret string
		want   string
		fail   string
	}{
		"default is bearer":   {CredentialHeader{}, "tok", "Bearer tok", ""},
		"whole secret":        {CredentialHeader{Name: "X-Key", Format: "{secret}"}, "abc", "abc", ""},
		"tenable two keys":    {CredentialHeader{Name: "X-ApiKeys", Format: "accessKey={accessKey};secretKey={secretKey}"}, `{"accessKey":"A1","secretKey":"S2"}`, "accessKey=A1;secretKey=S2", ""},
		"missing property":    {CredentialHeader{Format: "k={k}"}, `{"x":"1"}`, "", "has no property"},
		"not json":            {CredentialHeader{Format: "k={k}"}, `plain`, "", "not a JSON object"},
		"newline injection":   {CredentialHeader{Format: "{secret}"}, "a\r\nX-Evil: 1", "", "control character"},
		"newline in property": {CredentialHeader{Format: "k={k}"}, `{"k":"a\nb"}`, "", "control character"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.h.Value([]byte(tc.secret))
			if tc.fail != "" {
				if err == nil || !strings.Contains(err.Error(), tc.fail) {
					t.Fatalf("want error containing %q, got %v", tc.fail, err)
				}
				if strings.Contains(err.Error(), "S2") || strings.Contains(err.Error(), "plain") {
					t.Fatalf("the error holds credential material: %v", err)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestLoad_ConnectorConfigPolicy(t *testing.T) {
	rem := "id: x\nkind: connector\nspec:\n  class: scanner\n  shape: Remote\n  endpoint: https://a.example.com/mcp\n"
	host := "id: x\nkind: connector\nspec:\n  class: edr\n  shape: Hosted\n  image: quay.io/v/i@sha256:ab\n  auth: none\n"
	cases := map[string]struct{ body, want string }{
		"header without secret auth": {rem + "  auth: oauth\n  credentialHeader: {name: X-K, format: '{secret}'}\n", "credentialHeader needs a Remote connector with auth secret"},
		"header on Hosted":           {host + "  credentialHeader: {name: X-K}\n", "credentialHeader needs a Remote connector with auth secret"},
		"header host name":           {rem + "  auth: secret\n  credentialHeader: {name: Host}\n", "not a header that a connector can set"},
		"header bad name":            {rem + "  auth: secret\n  credentialHeader: {name: 'X K'}\n", "not a header that a connector can set"},
		"format no placeholder":      {rem + "  auth: secret\n  credentialHeader: {name: X-K, format: literal}\n", "no placeholder"},
		"format stray brace":         {rem + "  auth: secret\n  credentialHeader: {name: X-K, format: '{secret}}'}\n", "brace that is not part of a placeholder"},
		"scope without oauth":        {rem + "  auth: secret\n  oauthScope: read\n", "oauthScope needs auth oauth"},
		"client without oauth":       {rem + "  auth: none\n  oauthClient: tenant\n", "oauthClient needs auth oauth"},
		"bad client mode":            {rem + "  auth: oauth\n  oauthClient: both\n", "must be dynamic or tenant"},
		"env on Remote":              {rem + "  auth: none\n  env: {A: b}\n", "need a Hosted connector"},
		"port on Remote":             {rem + "  auth: none\n  port: 3000\n", "need a Hosted connector"},
		"plain secret variable":      {host + "  env: {FALCON_CLIENT_SECRET: abc}\n", "looks like a credential"},
		"plain token variable":       {host + "  env: {API_TOKEN: abc}\n", "looks like a credential"},
		"bad env name":               {host + "  env: {'1A': b}\n", "not a valid variable name"},
		"env newline":                {host + "  env: {A: \"b\\nc\"}\n", "control character"},
		"credential bad secret":      {host + "  credentials: [{secret: '../x', env: A}]\n", "not a valid secret name"},
		"credential bad env":         {host + "  credentials: [{secret: s, env: 'a-b'}]\n", "not a valid variable name"},
		"credential twice":           {host + "  credentials: [{secret: s, env: A}, {secret: t, env: A}]\n", "set twice"},
		"credential and env clash":   {host + "  credentials: [{secret: s, env: A}]\n  env: {A: b}\n", "set twice"},
		"empty arg":                  {host + "  args: ['']\n", "empty argument"},
		"low port":                   {host + "  port: 80\n", "from 1024 to 65535"},
		"high port":                  {host + "  port: 70000\n", "from 1024 to 65535"},
		"credential of the grant":    {host + "  credentials: [{secret: 'connector/x/grant', env: A}]\n", "not a valid secret name"},
		"pull secret of the access":  {host + "  imagePullSecret: 'connector/x/access'\n", "not a valid secret name"},
		"bad pull secret":            {host + "  imagePullSecret: 'a b'\n", "not a valid secret name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(manifestFSWith(map[string]string{"m.yaml": tc.body}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	ok := host + "  credentials: [{secret: s-id, env: CLIENT_ID}, {secret: s-sec, property: v, env: CLIENT_SECRET}]\n" +
		"  env: {BASE_URL: 'https://x.example.com'}\n  args: [--read-only]\n  port: 3000\n  imagePullSecret: pull\n"
	entries, err := load(manifestFSWith(map[string]string{"m.yaml": ok}))
	if err != nil {
		t.Fatalf("a valid Hosted manifest failed: %v", err)
	}
	e := entries[0].toConnectorEntry()
	if len(e.Credentials) != 2 || e.Port != 3000 || e.ImagePullSecret != "pull" || e.Args[0] != "--read-only" || e.Env["BASE_URL"] == "" {
		t.Fatalf("the projection lost a field: %+v", e)
	}
	if e.CredentialHeader.Name != "Authorization" || e.CredentialHeader.Format != "Bearer {secret}" {
		t.Fatalf("the default header is wrong: %+v", e.CredentialHeader)
	}
}
