package providers

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const expectedKeySize = 32

// KubernetesProvider retrieves encryption keys from Kubernetes Secrets.
type KubernetesProvider struct {
	client    kubernetes.Interface
	config    *crypto.KubernetesKeyConfig
	namespace string

	// Cached key (loaded once, immutable during pod lifetime)
	key     []byte
	keyOnce sync.Once
	keyErr  error
}

// NewKubernetesProvider creates a new Kubernetes Secrets key provider.
func NewKubernetesProvider(cfg *crypto.KubernetesKeyConfig) (*KubernetesProvider, error) {
	if cfg.SecretName == "" {
		return nil, fmt.Errorf("kubernetes.secret_name is required")
	}
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("kubernetes.secret_key is required")
	}

	// Use in-cluster config
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config (are you running in Kubernetes?): %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Determine namespace
	namespace := cfg.SecretNamespace
	if namespace == "" {
		// Try POD_NAMESPACE env var first
		if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
			namespace = ns
		} else {
			// Try reading from serviceaccount namespace file
			if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
				namespace = string(data)
			} else {
				return nil, fmt.Errorf("could not determine namespace: set security.key_provider.kubernetes.secret_namespace or POD_NAMESPACE env var")
			}
		}
	}

	return &KubernetesProvider{
		client:    clientset,
		config:    cfg,
		namespace: namespace,
	}, nil
}

// GetEncryptionKey retrieves the encryption key from the Kubernetes Secret.
func (p *KubernetesProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	p.keyOnce.Do(func() {
		secret, err := p.client.CoreV1().Secrets(p.namespace).Get(ctx, p.config.SecretName, metav1.GetOptions{})
		if err != nil {
			p.keyErr = fmt.Errorf("failed to get secret %s/%s: %w", p.namespace, p.config.SecretName, err)
			return
		}

		keyData, ok := secret.Data[p.config.SecretKey]
		if !ok {
			p.keyErr = fmt.Errorf("key %q not found in secret %s/%s", p.config.SecretKey, p.namespace, p.config.SecretName)
			return
		}

		if len(keyData) != expectedKeySize {
			p.keyErr = fmt.Errorf("invalid key size: expected %d bytes, got %d", expectedKeySize, len(keyData))
			return
		}

		// Copy to avoid holding reference to secret data
		p.key = make([]byte, expectedKeySize)
		copy(p.key, keyData)
	})

	if p.keyErr != nil {
		return nil, p.keyErr
	}
	return p.key, nil
}

// Name returns the provider identifier.
func (p *KubernetesProvider) Name() string {
	return "kubernetes"
}

// Health checks provider connectivity and key availability.
func (p *KubernetesProvider) Health(ctx context.Context) types.HealthStatus {
	_, err := p.GetEncryptionKey(ctx)
	if err != nil {
		return types.HealthStatus{
			State:   types.HealthStateUnhealthy,
			Message: fmt.Sprintf("key provider error: %v", err),
		}
	}
	return types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: fmt.Sprintf("key loaded from secret %s/%s", p.namespace, p.config.SecretName),
	}
}

// Close releases resources and zeros out the key from memory.
func (p *KubernetesProvider) Close() error {
	for i := range p.key {
		p.key[i] = 0
	}
	return nil
}
