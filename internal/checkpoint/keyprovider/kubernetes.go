package keyprovider

import (
	"context"
	"fmt"
	"os"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// expectedKeySize is the required key size for AES-256-GCM encryption
	expectedKeySize = 32

	// defaultDataKey is the default key name in the secret's data map
	defaultDataKey = "encryption-key"

	// defaultNamespaceFile is the path to the service account namespace file
	defaultNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// KubernetesKeyProvider retrieves encryption keys from Kubernetes Secrets.
//
// This provider supports both in-cluster and out-of-cluster (kubeconfig) configurations,
// making it suitable for both production deployments and local development.
//
// Key features:
//   - Automatic namespace detection via downward API or service account
//   - Lazy initialization of Kubernetes client
//   - Key validation (must be exactly 32 bytes for AES-256)
//   - Thread-safe for concurrent use
//   - Support for key rotation via key ID
type KubernetesKeyProvider struct {
	config KubernetesKeyProviderConfig

	// Kubernetes client (lazily initialized)
	client     kubernetes.Interface
	clientOnce sync.Once
	clientErr  error

	// Current key cache
	key     []byte
	keyOnce sync.Once
	keyErr  error

	// Key ID for the current key
	keyID string

	// Resolved namespace
	namespace string
}

// KubernetesKeyProviderConfig configures the Kubernetes Secrets key provider.
type KubernetesKeyProviderConfig struct {
	// Namespace is the Kubernetes namespace containing the secret.
	// If empty, will attempt to detect from:
	//   1. POD_NAMESPACE environment variable
	//   2. /var/run/secrets/kubernetes.io/serviceaccount/namespace
	Namespace string

	// SecretName is the name of the Kubernetes Secret containing the encryption key.
	// Required.
	SecretName string

	// DataKey is the key name within secret.data map.
	// Defaults to "encryption-key" if not specified.
	DataKey string

	// KubeconfigPath is the path to kubeconfig file for out-of-cluster development.
	// If empty, uses in-cluster config (service account credentials).
	KubeconfigPath string
}

// NewKubernetesKeyProvider creates a new Kubernetes Secrets key provider.
//
// The provider performs lazy initialization of the Kubernetes client and key retrieval.
// This allows configuration validation without requiring immediate API access.
//
// Returns an error if the configuration is invalid (e.g., missing secret name).
func NewKubernetesKeyProvider(config KubernetesKeyProviderConfig) (*KubernetesKeyProvider, error) {
	if config.SecretName == "" {
		return nil, fmt.Errorf("kubernetes: secret_name is required")
	}

	// Set default data key if not specified
	dataKey := config.DataKey
	if dataKey == "" {
		dataKey = defaultDataKey
	}

	// Resolve namespace
	namespace, err := resolveNamespace(config.Namespace)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: failed to resolve namespace: %w", err)
	}

	// Generate key ID from secret reference
	keyID := fmt.Sprintf("%s/%s:%s", namespace, config.SecretName, dataKey)

	return &KubernetesKeyProvider{
		config:    config,
		namespace: namespace,
		keyID:     keyID,
	}, nil
}

// GetKey retrieves the current encryption key from the Kubernetes Secret.
//
// The key is fetched once and cached for the lifetime of the provider.
// This is safe because Kubernetes Secrets are immutable during pod lifetime
// (changes require pod restart).
//
// Returns an error if:
//   - Kubernetes client initialization fails
//   - Secret does not exist or is inaccessible
//   - Key is not found in secret.data
//   - Key size is not exactly 32 bytes
func (p *KubernetesKeyProvider) GetKey(ctx context.Context) ([]byte, error) {
	// Ensure client is initialized
	if err := p.ensureClient(); err != nil {
		return nil, fmt.Errorf("kubernetes: client initialization failed: %w", err)
	}

	// Load and cache key on first access
	p.keyOnce.Do(func() {
		p.key, p.keyErr = p.fetchKey(ctx, p.config.SecretName, p.config.DataKey)
	})

	if p.keyErr != nil {
		return nil, p.keyErr
	}

	// Return a copy to prevent external modification
	keyCopy := make([]byte, len(p.key))
	copy(keyCopy, p.key)
	return keyCopy, nil
}

// GetKeyByID retrieves a specific encryption key by its identifier.
//
// For the Kubernetes provider, this currently supports only the current key ID.
// Future versions may support key rotation by storing multiple keys in the same
// secret or different secrets.
//
// Returns an error if the key ID is not recognized.
func (p *KubernetesKeyProvider) GetKeyByID(ctx context.Context, keyID string) ([]byte, error) {
	// For now, only support current key ID
	if keyID != p.keyID {
		return nil, fmt.Errorf("kubernetes: unknown key ID %q (current: %q)", keyID, p.keyID)
	}

	// Delegate to GetKey for current key
	return p.GetKey(ctx)
}

// CurrentKeyID returns the identifier of the current encryption key.
//
// The key ID format is: namespace/secret-name:data-key
// Example: "gibson-system/checkpoint-keys:encryption-key"
func (p *KubernetesKeyProvider) CurrentKeyID() string {
	return p.keyID
}

// ensureClient initializes the Kubernetes client if not already initialized.
//
// Uses sync.Once to ensure initialization happens exactly once, even with
// concurrent calls. Initialization errors are cached and returned on every call.
//
// The initialization process:
//  1. If KubeconfigPath is set, load configuration from that file (for local dev)
//  2. Otherwise, use in-cluster config (service account credentials)
//  3. Create clientset from the configuration
func (p *KubernetesKeyProvider) ensureClient() error {
	p.clientOnce.Do(func() {
		var config *rest.Config
		var err error

		// Try kubeconfig path first if configured (for local development)
		if p.config.KubeconfigPath != "" {
			config, err = clientcmd.BuildConfigFromFlags("", p.config.KubeconfigPath)
			if err != nil {
				p.clientErr = fmt.Errorf("failed to load kubeconfig from %s: %w",
					p.config.KubeconfigPath, err)
				return
			}
		} else {
			// Use in-cluster config (production)
			config, err = rest.InClusterConfig()
			if err != nil {
				p.clientErr = fmt.Errorf("failed to load in-cluster config: %w (hint: set kubeconfig_path for local development)", err)
				return
			}
		}

		// Create Kubernetes clientset
		p.client, p.clientErr = kubernetes.NewForConfig(config)
	})

	return p.clientErr
}

// fetchKey retrieves the encryption key from a Kubernetes Secret.
//
// This method performs the actual API call to fetch the secret and extract the key.
// It validates the key size to ensure it's suitable for AES-256-GCM encryption.
func (p *KubernetesKeyProvider) fetchKey(ctx context.Context, secretName, dataKey string) ([]byte, error) {
	// Get secret from Kubernetes API
	secret, err := p.client.CoreV1().Secrets(p.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", p.namespace, secretName, err)
	}

	// Check secret type (optional validation)
	if secret.Type != corev1.SecretTypeOpaque && secret.Type != "" {
		// Log warning but don't fail - secret type is informational
		// In production, you might want to enforce specific types
	}

	// Extract key from secret data
	keyData, ok := secret.Data[dataKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %s/%s (available keys: %v)",
			dataKey, p.namespace, secretName, getSecretKeys(secret))
	}

	// Validate key size for AES-256-GCM
	if len(keyData) != expectedKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes for AES-256, got %d bytes",
			expectedKeySize, len(keyData))
	}

	// Copy key to avoid holding reference to secret data
	key := make([]byte, expectedKeySize)
	copy(key, keyData)

	return key, nil
}

// resolveNamespace determines the Kubernetes namespace to use.
//
// Resolution order:
//  1. Use provided namespace if not empty
//  2. Check POD_NAMESPACE environment variable (set via downward API)
//  3. Read from service account namespace file
//  4. Return error if namespace cannot be determined
//
// This multi-step resolution ensures the provider works in various deployment scenarios.
func resolveNamespace(configNamespace string) (string, error) {
	// Use configured namespace if provided
	if configNamespace != "" {
		return configNamespace, nil
	}

	// Try POD_NAMESPACE environment variable (downward API)
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns, nil
	}

	// Try reading from service account namespace file (in-cluster)
	if data, err := os.ReadFile(defaultNamespaceFile); err == nil {
		ns := string(data)
		if ns != "" {
			return ns, nil
		}
	}

	// Unable to resolve namespace
	return "", fmt.Errorf("could not determine namespace: set namespace config, POD_NAMESPACE env var, or ensure service account is mounted")
}

// getSecretKeys returns a list of available keys in a secret for error messages.
func getSecretKeys(secret *corev1.Secret) []string {
	keys := make([]string, 0, len(secret.Data))
	for k := range secret.Data {
		keys = append(keys, k)
	}
	return keys
}
