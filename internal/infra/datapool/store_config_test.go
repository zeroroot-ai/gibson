// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"strings"
	"testing"
)

// A pool config gives each tenant connection its Redis client and its Neo4j
// session, so NewPool refuses a config without either, before it dials.
func TestValidateStoreConfig(t *testing.T) {
	full := Config{RedisAddr: "10.0.0.1:6379", Neo4jURI: "bolt://10.0.0.2:7687"}
	if err := validateStoreConfig(full); err != nil {
		t.Fatalf("a full config was refused: %v", err)
	}
	withResolver := Config{RedisAddr: "10.0.0.1:6379", Neo4jResolver: NewMultiDBResolver("bolt://10.0.0.2:7687", "", "")}
	if err := validateStoreConfig(withResolver); err != nil {
		t.Fatalf("a config with a Neo4j resolver was refused: %v", err)
	}
	for name, c := range map[string]struct {
		cfg  Config
		want string
	}{
		"no redis":    {Config{Neo4jURI: "bolt://10.0.0.2:7687"}, "RedisAddr is required"},
		"no neo4j":    {Config{RedisAddr: "10.0.0.1:6379"}, "Neo4j resolver or URI is required"},
		"half vector": {Config{RedisAddr: "10.0.0.1:6379", Neo4jURI: "bolt://x:7687", VectorStoreAddr: "10.0.0.1:6379"}, "must be set together"},
	} {
		err := validateStoreConfig(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to say %q", name, err, c.want)
		}
	}
	if _, err := NewPool(context.Background(), Config{Neo4jURI: "bolt://10.0.0.2:7687"}, fixedKeyProvider{}, nil); err == nil ||
		!strings.Contains(err.Error(), "RedisAddr is required") {
		t.Errorf("NewPool with no Redis: err = %v, want the store refusal", err)
	}
}
