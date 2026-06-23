package checkpoint

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIsSecretKey(t *testing.T) {
	tt := []struct {
		k    string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"db_password", true},
		{"vaultToken", true},
		{"token", true},
		{"refresh_token", true},
		{"client_secret", true},
		{"apikey", true},
		{"api_key", true},
		{"apiKey", true},
		{"credential", true},
		{"vault_credentials", true},
		{"private_key", true},
		{"privateKey", true},
		{"username", false},
		{"node_id", false},
		{"", false},
	}
	for _, tc := range tt {
		if got := IsSecretKey(tc.k); got != tc.want {
			t.Errorf("IsSecretKey(%q) = %v, want %v", tc.k, got, tc.want)
		}
	}
}

func TestRedactSecretsInJSONBytes_FlatMap(t *testing.T) {
	in := map[string]any{
		"username": "alice",
		"password": "supersecret",
		"api_key":  "AKIA-XXXX",
		"step":     int64(42),
	}
	raw, _ := json.Marshal(in)
	out := RedactSecretsInJSONBytes(raw)

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("redacted bytes should parse as JSON: %v", err)
	}
	if got["username"] != "alice" {
		t.Errorf("username should be untouched: %v", got["username"])
	}
	if got["password"] != RedactedPlaceholder {
		t.Errorf("password not redacted: %v", got["password"])
	}
	if got["api_key"] != RedactedPlaceholder {
		t.Errorf("api_key not redacted: %v", got["api_key"])
	}
	// step is a number, untouched
	if _, ok := got["step"].(float64); !ok {
		t.Errorf("step should remain numeric: %T %v", got["step"], got["step"])
	}
}

func TestRedactSecretsInJSONBytes_NestedMap(t *testing.T) {
	in := map[string]any{
		"db": map[string]any{
			"host":     "db.example.com",
			"password": "p",
		},
		"creds": []any{
			map[string]any{"name": "primary", "secret": "s"},
		},
	}
	raw, _ := json.Marshal(in)
	out := RedactSecretsInJSONBytes(raw)

	// Re-decode to compare structurally (json.Marshal may HTML-escape < and >).
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output should parse as JSON: %v", err)
	}
	if pwd := got["db"].(map[string]any)["password"]; pwd != RedactedPlaceholder {
		t.Errorf("password not redacted: %v", pwd)
	}
	if got["db"].(map[string]any)["host"] != "db.example.com" {
		t.Errorf("non-secret host should be untouched: %v", got["db"])
	}
	credList := got["creds"].([]any)
	credSecret := credList[0].(map[string]any)["secret"]
	if credSecret != RedactedPlaceholder {
		t.Errorf("nested secret not redacted: %v", credSecret)
	}
}

func TestRedactSecretsInJSONBytes_VaultPrefix(t *testing.T) {
	in := map[string]any{
		"upstream_token_resolver": "vault:secret/foo",
	}
	raw, _ := json.Marshal(in)
	out := RedactSecretsInJSONBytes(raw)
	if strings.Contains(string(out), "vault:secret/foo") {
		t.Errorf("vault-prefixed value not redacted: %s", out)
	}
}

func TestRedactSecretsInJSONBytes_VaultSourceAnnotation(t *testing.T) {
	in := map[string]any{
		"shared_creds": map[string]any{
			"source": "vault",
			"value":  "should-be-redacted",
		},
	}
	raw, _ := json.Marshal(in)
	out := RedactSecretsInJSONBytes(raw)
	if strings.Contains(string(out), "should-be-redacted") {
		t.Errorf("vault-source map should be redacted: %s", out)
	}
}

func TestRedactSecretsInJSONBytes_NonJSONPassthrough(t *testing.T) {
	in := []byte{0x82, 0xa5} // msgpack-shaped bytes
	out := RedactSecretsInJSONBytes(in)
	if string(out) != string(in) {
		t.Errorf("non-JSON bytes should be returned unchanged")
	}
}

func TestRedactSecretsInJSONBytes_Empty(t *testing.T) {
	if got := RedactSecretsInJSONBytes(nil); got != nil {
		t.Errorf("nil input should return nil, got %v", got)
	}
	if got := RedactSecretsInJSONBytes([]byte{}); len(got) != 0 {
		t.Errorf("empty input should return empty, got %v", got)
	}
}
