package keyprovider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestNewKubernetesKeyProvider(t *testing.T) {
	tests := []struct {
		name        string
		config      KubernetesKeyProviderConfig
		setupEnv    func()
		cleanupEnv  func()
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config with explicit namespace",
			config: KubernetesKeyProviderConfig{
				Namespace:  "test-namespace",
				SecretName: "test-secret",
				DataKey:    "encryption-key",
			},
			wantErr: false,
		},
		{
			name: "valid config with default data key",
			config: KubernetesKeyProviderConfig{
				Namespace:  "test-namespace",
				SecretName: "test-secret",
				DataKey:    "", // Should default to "encryption-key"
			},
			wantErr: false,
		},
		{
			name: "valid config with POD_NAMESPACE env",
			config: KubernetesKeyProviderConfig{
				Namespace:  "", // Will use env var
				SecretName: "test-secret",
			},
			setupEnv: func() {
				t.Setenv("POD_NAMESPACE", "env-namespace")
			},
			wantErr: false,
		},
		{
			name: "missing secret name",
			config: KubernetesKeyProviderConfig{
				Namespace: "test-namespace",
			},
			wantErr:     true,
			errContains: "secret_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			if tt.cleanupEnv != nil {
				defer tt.cleanupEnv()
			}

			provider, err := NewKubernetesKeyProvider(tt.config)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, provider)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, provider)
				assert.NotEmpty(t, provider.CurrentKeyID())
			}
		})
	}
}

func TestKubernetesKeyProvider_GetKey(t *testing.T) {
	// Generate a valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	tests := []struct {
		name        string
		namespace   string
		secretName  string
		dataKey     string
		setupClient func() *fake.Clientset
		wantErr     bool
		errContains string
		validate    func(t *testing.T, key []byte)
	}{
		{
			name:       "successful key retrieval",
			namespace:  "test-ns",
			secretName: "test-secret",
			dataKey:    "encryption-key",
			setupClient: func() *fake.Clientset {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test-ns",
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"encryption-key": validKey,
					},
				}
				return fake.NewSimpleClientset(secret)
			},
			wantErr: false,
			validate: func(t *testing.T, key []byte) {
				assert.Equal(t, validKey, key)
				assert.Len(t, key, 32)
			},
		},
		{
			name:       "secret not found",
			namespace:  "test-ns",
			secretName: "missing-secret",
			dataKey:    "encryption-key",
			setupClient: func() *fake.Clientset {
				// Empty clientset, no secrets
				return fake.NewSimpleClientset()
			},
			wantErr:     true,
			errContains: "not found",
		},
		{
			name:       "key not found in secret",
			namespace:  "test-ns",
			secretName: "test-secret",
			dataKey:    "missing-key",
			setupClient: func() *fake.Clientset {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test-ns",
					},
					Data: map[string][]byte{
						"different-key": validKey,
					},
				}
				return fake.NewSimpleClientset(secret)
			},
			wantErr:     true,
			errContains: "not found in secret",
		},
		{
			name:       "invalid key size - too short",
			namespace:  "test-ns",
			secretName: "test-secret",
			dataKey:    "encryption-key",
			setupClient: func() *fake.Clientset {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test-ns",
					},
					Data: map[string][]byte{
						"encryption-key": []byte("too-short-key"), // Only 13 bytes
					},
				}
				return fake.NewSimpleClientset(secret)
			},
			wantErr:     true,
			errContains: "invalid key size: expected 32 bytes",
		},
		{
			name:       "invalid key size - too long",
			namespace:  "test-ns",
			secretName: "test-secret",
			dataKey:    "encryption-key",
			setupClient: func() *fake.Clientset {
				longKey := make([]byte, 64) // 64 bytes, too long
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test-ns",
					},
					Data: map[string][]byte{
						"encryption-key": longKey,
					},
				}
				return fake.NewSimpleClientset(secret)
			},
			wantErr:     true,
			errContains: "invalid key size: expected 32 bytes",
		},
		{
			name:       "kubernetes api error",
			namespace:  "test-ns",
			secretName: "test-secret",
			dataKey:    "encryption-key",
			setupClient: func() *fake.Clientset {
				client := fake.NewSimpleClientset()
				// Inject error on Get operation
				client.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("api server unavailable")
				})
				return client
			},
			wantErr:     true,
			errContains: "api server unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()

			provider := &KubernetesKeyProvider{
				config: KubernetesKeyProviderConfig{
					Namespace:  tt.namespace,
					SecretName: tt.secretName,
					DataKey:    tt.dataKey,
				},
				client:    client,
				namespace: tt.namespace,
				keyID:     fmt.Sprintf("%s/%s:%s", tt.namespace, tt.secretName, tt.dataKey),
			}
			// Mark client as initialized to prevent ensureClient from trying to reinitialize
			provider.clientOnce.Do(func() {
				// Client is already set, nothing to do
			})

			ctx := context.Background()
			key, err := provider.GetKey(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, key)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, key)
				if tt.validate != nil {
					tt.validate(t, key)
				}
			}
		})
	}
}

func TestKubernetesKeyProvider_GetKey_Caching(t *testing.T) {
	// Generate a valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"encryption-key": validKey,
		},
	}

	client := fake.NewSimpleClientset(secret)

	// Track API calls
	callCount := 0
	client.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		callCount++
		return false, nil, nil // Continue with default behavior
	})

	provider := &KubernetesKeyProvider{
		config: KubernetesKeyProviderConfig{
			Namespace:  "test-ns",
			SecretName: "test-secret",
			DataKey:    "encryption-key",
		},
		client:    client,
		namespace: "test-ns",
		keyID:     "test-ns/test-secret:encryption-key",
	}
	// Mark client as initialized to prevent ensureClient from trying to reinitialize
	provider.clientOnce.Do(func() {
		// Client is already set, nothing to do
	})

	ctx := context.Background()

	// First call - should hit API
	key1, err := provider.GetKey(ctx)
	require.NoError(t, err)
	assert.Equal(t, validKey, key1)
	assert.Equal(t, 1, callCount, "First call should hit API")

	// Second call - should use cache
	key2, err := provider.GetKey(ctx)
	require.NoError(t, err)
	assert.Equal(t, validKey, key2)
	assert.Equal(t, 1, callCount, "Second call should use cache, not hit API again")

	// Verify keys are independent copies
	key1[0] = 0xFF
	assert.NotEqual(t, key1[0], key2[0], "Keys should be independent copies")
}

func TestKubernetesKeyProvider_GetKeyByID(t *testing.T) {
	// Generate a valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"encryption-key": validKey,
		},
	}

	client := fake.NewSimpleClientset(secret)

	provider := &KubernetesKeyProvider{
		config: KubernetesKeyProviderConfig{
			Namespace:  "test-ns",
			SecretName: "test-secret",
			DataKey:    "encryption-key",
		},
		client:    client,
		namespace: "test-ns",
		keyID:     "test-ns/test-secret:encryption-key",
	}
	// Mark client as initialized to prevent ensureClient from trying to reinitialize
	provider.clientOnce.Do(func() {
		// Client is already set, nothing to do
	})

	ctx := context.Background()

	t.Run("get current key by ID", func(t *testing.T) {
		key, err := provider.GetKeyByID(ctx, provider.CurrentKeyID())
		require.NoError(t, err)
		assert.Equal(t, validKey, key)
	})

	t.Run("get unknown key ID", func(t *testing.T) {
		key, err := provider.GetKeyByID(ctx, "unknown-key-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown key ID")
		assert.Nil(t, key)
	})
}

func TestKubernetesKeyProvider_CurrentKeyID(t *testing.T) {
	tests := []struct {
		name       string
		namespace  string
		secretName string
		dataKey    string
		wantKeyID  string
	}{
		{
			name:       "standard key ID format",
			namespace:  "gibson-system",
			secretName: "checkpoint-keys",
			dataKey:    "encryption-key",
			wantKeyID:  "gibson-system/checkpoint-keys:encryption-key",
		},
		{
			name:       "custom data key",
			namespace:  "prod",
			secretName: "my-secret",
			dataKey:    "custom-key",
			wantKeyID:  "prod/my-secret:custom-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &KubernetesKeyProvider{
				namespace: tt.namespace,
				keyID:     fmt.Sprintf("%s/%s:%s", tt.namespace, tt.secretName, tt.dataKey),
			}

			keyID := provider.CurrentKeyID()
			assert.Equal(t, tt.wantKeyID, keyID)
		})
	}
}

func TestKubernetesKeyProvider_InterfaceCompliance(t *testing.T) {
	// Compile-time check that KubernetesKeyProvider implements KeyProvider
	var _ KeyProvider = (*KubernetesKeyProvider)(nil)
}

func TestResolveNamespace(t *testing.T) {
	tests := []struct {
		name          string
		configNS      string
		setupEnv      func()
		wantNamespace string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "use config namespace",
			configNS:      "config-namespace",
			wantNamespace: "config-namespace",
			wantErr:       false,
		},
		{
			name:     "use POD_NAMESPACE env",
			configNS: "",
			setupEnv: func() {
				t.Setenv("POD_NAMESPACE", "env-namespace")
			},
			wantNamespace: "env-namespace",
			wantErr:       false,
		},
		{
			name:     "config takes precedence over env",
			configNS: "config-namespace",
			setupEnv: func() {
				t.Setenv("POD_NAMESPACE", "env-namespace")
			},
			wantNamespace: "config-namespace",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv()
			}

			namespace, err := resolveNamespace(tt.configNS)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantNamespace, namespace)
			}
		})
	}
}

func TestGetSecretKeys(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
			"key3": []byte("value3"),
		},
	}

	keys := getSecretKeys(secret)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, "key1")
	assert.Contains(t, keys, "key2")
	assert.Contains(t, keys, "key3")
}

func TestGetSecretKeys_EmptySecret(t *testing.T) {
	secret := &corev1.Secret{
		Data: map[string][]byte{},
	}

	keys := getSecretKeys(secret)
	assert.Len(t, keys, 0)
}
