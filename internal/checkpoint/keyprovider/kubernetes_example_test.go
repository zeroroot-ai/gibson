package keyprovider_test

import (
	"fmt"
	"log"

	"github.com/zero-day-ai/gibson/internal/checkpoint/keyprovider"
)

// Example_kubernetesKeyProvider demonstrates basic usage of the Kubernetes key provider.
//
// Note: This example shows the API usage pattern but doesn't execute in tests
// since it requires a Kubernetes cluster with the appropriate secrets configured.
func Example_kubernetesKeyProvider() {
	// Create a configuration for the Kubernetes key provider
	config := keyprovider.KubernetesKeyProviderConfig{
		// Namespace can be auto-detected from POD_NAMESPACE env var
		// or /var/run/secrets/kubernetes.io/serviceaccount/namespace
		Namespace: "gibson-system",

		// Name of the Kubernetes Secret containing the encryption key
		SecretName: "checkpoint-encryption-keys",

		// Key name in the secret's data map (defaults to "encryption-key" if empty)
		DataKey: "encryption-key",

		// Optional: path to kubeconfig for local development
		// Leave empty to use in-cluster configuration in production
		// KubeconfigPath: "/path/to/kubeconfig",
	}

	// Create the key provider
	provider, err := keyprovider.NewKubernetesKeyProvider(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes key provider: %v", err)
	}

	// In a real deployment, you would:
	// ctx := context.Background()
	// key, err := provider.GetKey(ctx)
	// if err != nil {
	//     log.Fatalf("Failed to get encryption key: %v", err)
	// }

	// For this example, we just show the configuration
	fmt.Printf("Provider configured with key ID: %s\n", provider.CurrentKeyID())

	// Output:
	// Provider configured with key ID: gibson-system/checkpoint-encryption-keys:encryption-key
}

// ExampleKubernetesKeyProvider_configuration shows various configuration patterns.
//
// This demonstrates how to configure the Kubernetes key provider for different scenarios
// but doesn't execute real API calls in the test environment.
func ExampleKubernetesKeyProvider_configuration() {
	// Example 1: Auto-detect namespace (production deployment)
	// When namespace is not specified, it will be auto-detected in this order:
	// 1. POD_NAMESPACE environment variable (set via Downward API)
	// 2. /var/run/secrets/kubernetes.io/serviceaccount/namespace file
	_ = keyprovider.KubernetesKeyProviderConfig{
		SecretName: "checkpoint-keys",
		DataKey:    "encryption-key",
		// Namespace is intentionally empty - will be auto-detected
	}

	// Example 2: Local development with kubeconfig
	_ = keyprovider.KubernetesKeyProviderConfig{
		Namespace:      "dev",
		SecretName:     "local-checkpoint-keys",
		DataKey:        "dev-key",
		KubeconfigPath: "/home/developer/.kube/config",
	}

	// Example 3: Explicit namespace (recommended for clarity)
	config := keyprovider.KubernetesKeyProviderConfig{
		Namespace:  "production",
		SecretName: "checkpoint-keys",
		DataKey:    "encryption-key",
	}

	provider, err := keyprovider.NewKubernetesKeyProvider(config)
	if err != nil {
		log.Printf("Failed to create provider: %v", err)
		return
	}

	fmt.Printf("Provider configured with key ID: %s\n", provider.CurrentKeyID())

	// Output:
	// Provider configured with key ID: production/checkpoint-keys:encryption-key
}
