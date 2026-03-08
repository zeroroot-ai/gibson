package memory

import (
	"strings"
	"testing"
)

func TestLongTermMemoryConfig_Validate_SQLiteRejected(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "sqlite",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for sqlite backend, but it passed")
	}
	
	if !strings.Contains(err.Error(), "invalid backend 'sqlite'") {
		t.Errorf("Expected error about invalid backend, got: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_QdrantWithoutConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "qdrant",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for qdrant without connection_url, but it passed")
	}
	
	if !strings.Contains(err.Error(), "connection_url is required") {
		t.Errorf("Expected error about connection_url required, got: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_QdrantWithConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend:       "qdrant",
		ConnectionURL: "http://localhost:6333",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err != nil {
		t.Fatalf("Expected validation to pass for qdrant with connection_url, got error: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_MilvusWithoutConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "milvus",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for milvus without connection_url, but it passed")
	}
	
	if !strings.Contains(err.Error(), "connection_url is required") {
		t.Errorf("Expected error about connection_url required, got: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_MilvusWithConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend:       "milvus",
		ConnectionURL: "localhost:19530",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err != nil {
		t.Fatalf("Expected validation to pass for milvus with connection_url, got error: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_RedisWithoutConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "redis",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for redis without connection_url, but it passed")
	}
	
	if !strings.Contains(err.Error(), "connection_url is required") {
		t.Errorf("Expected error about connection_url required, got: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_RedisWithConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend:       "redis",
		ConnectionURL: "redis://localhost:6379",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err != nil {
		t.Fatalf("Expected validation to pass for redis with connection_url, got error: %v", err)
	}
}

func TestLongTermMemoryConfig_Validate_EmbeddedNoConnectionURL(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "embedded",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err != nil {
		t.Fatalf("Expected validation to pass for embedded backend without connection_url, got error: %v", err)
	}
}

func TestEmbedderConfig_Validate_OpenAIRejected(t *testing.T) {
	config := &EmbedderConfig{
		Provider: "openai",
	}
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for openai provider, but it passed")
	}
	
	if !strings.Contains(err.Error(), "invalid embedder provider 'openai'") {
		t.Errorf("Expected error about invalid embedder provider, got: %v", err)
	}
}

func TestEmbedderConfig_Validate_NativeAccepted(t *testing.T) {
	config := &EmbedderConfig{
		Provider: "native",
	}
	
	err := config.Validate()
	if err != nil {
		t.Fatalf("Expected validation to pass for native provider, got error: %v", err)
	}
}

func TestValidBackendsIncludesExpectedBackends(t *testing.T) {
	// Test that all expected backends are accepted
	expectedBackends := []string{"embedded", "redis", "qdrant", "milvus"}
	
	for _, backend := range expectedBackends {
		config := &LongTermMemoryConfig{
			Backend: backend,
		}
		config.Embedder.ApplyDefaults()
		
		// For non-embedded backends, add connection_url to pass full validation
		if backend != "embedded" {
			config.ConnectionURL = "http://localhost:1234"
		}
		
		err := config.Validate()
		if err != nil {
			t.Errorf("Expected backend '%s' to be valid, got error: %v", backend, err)
		}
	}
}

func TestValidBackendsErrorMessage(t *testing.T) {
	config := &LongTermMemoryConfig{
		Backend: "invalid_backend",
	}
	config.Embedder.ApplyDefaults()
	
	err := config.Validate()
	if err == nil {
		t.Fatal("Expected validation to fail for invalid backend")
	}
	
	expectedBackends := []string{"embedded", "redis", "qdrant", "milvus"}
	for _, backend := range expectedBackends {
		if !strings.Contains(err.Error(), backend) {
			t.Errorf("Expected error message to mention '%s', got: %v", backend, err)
		}
	}
}
