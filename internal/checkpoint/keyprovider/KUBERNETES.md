# Kubernetes Secrets Key Provider

The Kubernetes Secrets key provider retrieves encryption keys from Kubernetes Secrets for checkpoint encryption. This provider is designed for Kubernetes-native deployments and supports both in-cluster and local development scenarios.

## Features

- **Automatic Namespace Detection**: Resolves namespace from configuration, environment variables, or service account
- **Dual Configuration Mode**: Supports both in-cluster (production) and kubeconfig (development) configurations
- **Key Validation**: Enforces AES-256 key size requirements (32 bytes)
- **Thread-Safe**: Safe for concurrent access with proper synchronization
- **Lazy Initialization**: Kubernetes client and keys are loaded on first use
- **Key Caching**: Keys are fetched once and cached for the pod lifetime
- **Error Handling**: Comprehensive error messages for troubleshooting

## Architecture

The provider follows these key design principles:

1. **Immutability**: Keys are treated as immutable during pod lifetime. Key rotation requires pod restart.
2. **Fail-Fast**: Configuration validation happens early, but API calls are deferred until first use.
3. **Security**: Keys are copied to prevent external modification. Sensitive operations use proper error wrapping.
4. **Observability**: Clear error messages include context (namespace, secret name, available keys).

## Configuration

### Basic Configuration

```go
config := keyprovider.KubernetesKeyProviderConfig{
    Namespace:  "gibson-system",
    SecretName: "checkpoint-encryption-keys",
    DataKey:    "encryption-key",
}

provider, err := keyprovider.NewKubernetesKeyProvider(config)
if err != nil {
    log.Fatalf("Failed to create key provider: %v", err)
}
```

### Configuration Options

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Namespace` | string | No* | Kubernetes namespace containing the secret. Auto-detected if empty. |
| `SecretName` | string | Yes | Name of the Kubernetes Secret. |
| `DataKey` | string | No | Key name in secret.data map. Defaults to "encryption-key". |
| `KubeconfigPath` | string | No | Path to kubeconfig for local development. Uses in-cluster config if empty. |

*Note: `Namespace` is auto-detected in this order:
1. Configured value (if provided)
2. `POD_NAMESPACE` environment variable
3. `/var/run/secrets/kubernetes.io/serviceaccount/namespace` file

### Production Configuration (In-Cluster)

For production deployments running in Kubernetes:

```go
config := keyprovider.KubernetesKeyProviderConfig{
    SecretName: "checkpoint-keys",
    // Namespace auto-detected from POD_NAMESPACE or service account
    // Uses in-cluster config automatically
}
```

### Development Configuration (Local)

For local development with kubeconfig:

```go
config := keyprovider.KubernetesKeyProviderConfig{
    Namespace:      "dev",
    SecretName:     "checkpoint-keys",
    KubeconfigPath: os.ExpandEnv("$HOME/.kube/config"),
}
```

## Kubernetes Secret Setup

### Creating the Encryption Key Secret

Generate a secure 32-byte encryption key:

```bash
# Generate a random 32-byte key (base64 encoded)
openssl rand -base64 32 > encryption-key.txt

# Create Kubernetes secret
kubectl create secret generic checkpoint-encryption-keys \
  --from-file=encryption-key=encryption-key.txt \
  --namespace=gibson-system

# Clean up the key file
rm encryption-key.txt
```

### Using kubectl directly

```bash
# Generate key inline
kubectl create secret generic checkpoint-encryption-keys \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --namespace=gibson-system
```

### Using a manifest

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: checkpoint-encryption-keys
  namespace: gibson-system
type: Opaque
data:
  # Base64-encoded 32-byte key
  encryption-key: <base64-encoded-32-byte-key>
```

Apply the manifest:

```bash
kubectl apply -f secret.yaml
```

## Deployment Configuration

### Pod with Downward API (Recommended)

Use the Downward API to inject the pod's namespace:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gibson-agent
  namespace: gibson-system
spec:
  containers:
  - name: agent
    image: gibson-agent:latest
    env:
    - name: POD_NAMESPACE
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace
  serviceAccountName: gibson-agent
```

### ServiceAccount with RBAC

Grant the pod's ServiceAccount permission to read the secret:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gibson-agent
  namespace: gibson-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: checkpoint-key-reader
  namespace: gibson-system
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["checkpoint-encryption-keys"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gibson-agent-key-reader
  namespace: gibson-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: checkpoint-key-reader
subjects:
- kind: ServiceAccount
  name: gibson-agent
  namespace: gibson-system
```

## Usage

### Basic Usage

```go
ctx := context.Background()

// Get current encryption key
key, err := provider.GetKey(ctx)
if err != nil {
    return fmt.Errorf("failed to get encryption key: %w", err)
}

// Use key for encryption/decryption
// ...
```

### Key ID Management

```go
// Get current key ID (format: namespace/secret-name:data-key)
keyID := provider.CurrentKeyID()
fmt.Println("Current key ID:", keyID)
// Output: gibson-system/checkpoint-encryption-keys:encryption-key

// Retrieve key by ID (useful for decryption)
key, err := provider.GetKeyByID(ctx, keyID)
if err != nil {
    return fmt.Errorf("failed to get key by ID: %w", err)
}
```

### Error Handling

```go
key, err := provider.GetKey(ctx)
if err != nil {
    // Errors include helpful context
    // Examples:
    // - "failed to get secret gibson-system/checkpoint-keys: not found"
    // - "key 'encryption-key' not found in secret (available keys: [old-key, backup-key])"
    // - "invalid key size: expected 32 bytes, got 16"
    log.Printf("Key retrieval failed: %v", err)
    return err
}
```

## Key Rotation

The Kubernetes key provider currently supports single-key usage. For key rotation:

1. **Create new secret** with the new key
2. **Update deployment** to reference the new secret
3. **Restart pods** to pick up the new key

Future versions may support multi-key rotation with backward compatibility.

### Rotation Example

```bash
# Create new key secret
kubectl create secret generic checkpoint-encryption-keys-v2 \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --namespace=gibson-system

# Update deployment to use new secret
# Update SecretName in configuration: "checkpoint-encryption-keys-v2"

# Restart pods
kubectl rollout restart deployment/gibson-agent -n gibson-system
```

## Security Considerations

### Key Security

- **Never commit keys** to version control
- **Use Sealed Secrets** or external secret managers for GitOps workflows
- **Rotate keys regularly** following your security policy
- **Audit access** to the encryption key secret
- **Restrict RBAC** to only pods that need encryption keys

### Namespace Isolation

- Deploy secrets in the same namespace as the pods using them
- Use NetworkPolicies to restrict pod-to-pod communication
- Consider using separate namespaces for different security zones

### Secret Encryption at Rest

Ensure Kubernetes secrets are encrypted at rest:

```yaml
# Enable encryption at rest in kube-apiserver
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-encoded-secret>
    - identity: {}
```

## Troubleshooting

### Common Errors

#### "kubernetes: secret_name is required"

**Cause**: Missing SecretName in configuration.

**Fix**: Provide a secret name:
```go
config.SecretName = "checkpoint-encryption-keys"
```

#### "could not determine namespace"

**Cause**: Namespace not configured and cannot be auto-detected.

**Fix**: Set namespace explicitly or ensure POD_NAMESPACE is set:
```yaml
env:
- name: POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
```

#### "failed to load in-cluster config"

**Cause**: Running outside Kubernetes without kubeconfig.

**Fix**: Set KubeconfigPath for local development:
```go
config.KubeconfigPath = os.ExpandEnv("$HOME/.kube/config")
```

#### "secret not found"

**Cause**: Secret doesn't exist or pod lacks RBAC permissions.

**Fix**:
1. Verify secret exists: `kubectl get secret <name> -n <namespace>`
2. Check RBAC permissions for the ServiceAccount
3. Verify namespace is correct

#### "key not found in secret"

**Cause**: The specified DataKey doesn't exist in the secret.

**Fix**: Check available keys:
```bash
kubectl get secret checkpoint-encryption-keys -n gibson-system -o jsonpath='{.data}'
```

#### "invalid key size: expected 32 bytes"

**Cause**: Key in secret is not 32 bytes.

**Fix**: Generate a proper 32-byte key:
```bash
openssl rand -bytes 32 | base64
```

### Debugging

Enable verbose logging to see detailed errors:

```go
key, err := provider.GetKey(ctx)
if err != nil {
    log.Printf("Full error: %+v", err)
    // Errors are wrapped with context for easy debugging
}
```

Check Kubernetes events:
```bash
kubectl get events -n gibson-system --sort-by='.lastTimestamp'
```

Verify RBAC permissions:
```bash
kubectl auth can-i get secrets/checkpoint-encryption-keys \
  --as=system:serviceaccount:gibson-system:gibson-agent \
  -n gibson-system
```

## Performance Considerations

- **Key Caching**: Keys are loaded once and cached. No repeated API calls.
- **Lazy Initialization**: Kubernetes client created only when first needed.
- **Thread-Safe**: Multiple goroutines can safely call GetKey() concurrently.
- **No Polling**: Provider doesn't watch for secret changes. Requires pod restart for updates.

## Best Practices

1. **Use Downward API** for namespace injection
2. **Grant minimal RBAC** permissions (only 'get' on specific secret)
3. **Separate secrets** for different environments (dev, staging, prod)
4. **Automate key rotation** with proper versioning
5. **Monitor secret access** via audit logs
6. **Use encryption at rest** for all secrets
7. **Test locally** with kubeconfig before deploying

## Integration with External Secret Managers

For production, consider using external secret managers:

### External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: checkpoint-encryption-keys
  namespace: gibson-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: checkpoint-encryption-keys
  data:
  - secretKey: encryption-key
    remoteRef:
      key: gibson/checkpoint/encryption-key
```

### Sealed Secrets

```bash
# Encrypt secret for GitOps
kubeseal --format yaml < secret.yaml > sealed-secret.yaml

# Commit sealed-secret.yaml to git
git add sealed-secret.yaml
git commit -m "Add encrypted checkpoint key"
```

## API Reference

See [interface.go](interface.go) for the KeyProvider interface documentation.

### Key Methods

- `GetKey(ctx context.Context) ([]byte, error)` - Retrieve current encryption key
- `GetKeyByID(ctx context.Context, keyID string) ([]byte, error)` - Retrieve specific key by ID
- `CurrentKeyID() string` - Get current key identifier

### Key ID Format

Key IDs follow the format: `namespace/secret-name:data-key`

Examples:
- `gibson-system/checkpoint-keys:encryption-key`
- `prod/encryption-secrets:aes-key-v2`
