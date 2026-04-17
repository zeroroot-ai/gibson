package manifest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManifestKeysHandler_ReturnsPublishedKeys(t *testing.T) {
	k1, _ := GenerateSignerKey("k1")
	k2, _ := GenerateSignerKey("k2")
	s, _ := NewSigner("k2", []SignerKey{k1, k2})
	srv := httptest.NewServer(ManifestKeysHandler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}

	var doc ManifestKeysDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(doc.ManifestSigningKeys) != 2 {
		t.Fatalf("keys len = %d", len(doc.ManifestSigningKeys))
	}
	// Active kid first.
	if doc.ManifestSigningKeys[0].Kid != "k2" {
		t.Fatalf("active kid = %q, want k2", doc.ManifestSigningKeys[0].Kid)
	}
	for _, k := range doc.ManifestSigningKeys {
		if k.Alg != "EdDSA" || k.Kty != "OKP" || k.Crv != "Ed25519" {
			t.Fatalf("unexpected JWK header: %+v", k)
		}
		if k.X == "" {
			t.Fatalf("kid %q missing x", k.Kid)
		}
	}
}

func TestManifestKeysHandler_NilSigner503(t *testing.T) {
	srv := httptest.NewServer(ManifestKeysHandler(nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestManifestKeysHandler_MethodNotAllowed(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	srv := httptest.NewServer(ManifestKeysHandler(s))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestMergeManifestKeys_DoesNotOverride(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	existing := map[string]any{
		"protocol_version":      "1.0",
		"manifest_signing_keys": "pre-existing",
	}
	out := MergeManifestKeys(existing, s)
	if got, ok := out["manifest_signing_keys"].(string); !ok || got != "pre-existing" {
		t.Fatalf("expected existing key preserved, got %v", out["manifest_signing_keys"])
	}
}

func TestMergeManifestKeys_AddsWhenAbsent(t *testing.T) {
	k, _ := GenerateSignerKey("k1")
	s, _ := NewSigner("k1", []SignerKey{k})
	existing := map[string]any{"protocol_version": "1.0"}
	out := MergeManifestKeys(existing, s)
	keys, ok := out["manifest_signing_keys"].([]SigningKeyJWK)
	if !ok {
		t.Fatalf("manifest_signing_keys type = %T", out["manifest_signing_keys"])
	}
	if len(keys) != 1 || keys[0].Kid != "k1" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
}
