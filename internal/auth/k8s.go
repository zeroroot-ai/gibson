package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// K8sValidator validates Kubernetes ServiceAccount tokens using TokenReview API.
//
// Implements the Authenticator interface.
// Thread-safe for concurrent use.
//
// This validator is used for authenticating workloads running in Kubernetes
// (ArgoCD, Tekton pipelines, custom operators) using their ServiceAccount tokens.
type K8sValidator struct {
	config       *K8sAuthConfig
	client       kubernetes.Interface
	clientOnce   sync.Once
	clientErr    error
	roleBinder   *RoleBinder
	roleBindings map[string][]string
}

// NewK8sValidator creates a new Kubernetes token validator.
//
// The validator lazily initializes the Kubernetes client on first use.
// This allows configuration to be loaded without requiring K8s API access
// at startup.
//
// When cfg is nil, a default empty config is used (no role bindings).
// The Enabled field is ignored — callers that want to skip K8s auth
// should simply not call this function.
//
// Returns an error only if role binder creation fails.
func NewK8sValidator(cfg *K8sAuthConfig) (*K8sValidator, error) {
	if cfg == nil {
		cfg = &K8sAuthConfig{
			Enabled:      true,
			RoleBindings: map[string][]string{},
		}
	}

	// Initialize role binder with K8s-specific bindings
	roleBinder := NewRoleBinderFromConfig(cfg.RoleBindings)

	return &K8sValidator{
		config:       cfg,
		roleBinder:   roleBinder,
		roleBindings: cfg.RoleBindings,
	}, nil
}

// Authenticate validates a ServiceAccount token via TokenReview API.
//
// Process:
//  1. Call Kubernetes TokenReview API to validate the token
//  2. Extract namespace and ServiceAccount name from result
//  3. Map to Identity with namespace:serviceaccount format
//  4. Apply role bindings based on SA identity
//
// Returns Identity if token is valid, error otherwise.
func (v *K8sValidator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	startTime := time.Now()
	defer func() {
		latencyMs := float64(time.Since(startTime).Milliseconds())
		recordAuthLatency(ctx, "kubernetes", latencyMs)
	}()

	// Ensure client is initialized
	if err := v.ensureClient(); err != nil {
		recordAuthAttempt(ctx, "kubernetes", "error")
		return nil, fmt.Errorf("k8s client initialization failed: %w", err)
	}

	// Create TokenReview request
	tokenReview := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	// Call TokenReview API
	result, err := v.client.AuthenticationV1().TokenReviews().Create(
		ctx,
		tokenReview,
		metav1.CreateOptions{},
	)
	if err != nil {
		recordAuthAttempt(ctx, "kubernetes", "error")
		return nil, ErrK8sAPIError(err)
	}

	// Check if token is authenticated
	if !result.Status.Authenticated {
		recordAuthAttempt(ctx, "kubernetes", "failure")
		if result.Status.Error != "" {
			return nil, ErrInvalidToken(fmt.Errorf("tokenreview error: %s", result.Status.Error))
		}
		return nil, ErrInvalidToken(fmt.Errorf("token not authenticated"))
	}

	// Extract user info
	userInfo := result.Status.User
	if userInfo.Username == "" {
		return nil, ErrMalformedToken(fmt.Errorf("empty username in tokenreview response"))
	}

	// Parse ServiceAccount username format: system:serviceaccount:<namespace>:<name>
	namespace, saName, err := parseServiceAccountUsername(userInfo.Username)
	if err != nil {
		return nil, ErrMalformedToken(fmt.Errorf("invalid serviceaccount username format: %w", err))
	}

	// Build subject in format "namespace:serviceaccount"
	subject := fmt.Sprintf("%s:%s", namespace, saName)

	// Build claims map
	claims := map[string]any{
		"username":        userInfo.Username,
		"namespace":       namespace,
		"serviceaccount":  saName,
		"uid":             userInfo.UID,
		"groups":          userInfo.Groups,
		"extra":           userInfo.Extra,
		"authentication":  "kubernetes",
	}

	// Build identity
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         subject,
			Issuer:          "kubernetes",
			Email:           "", // ServiceAccounts don't have emails
			Groups:          userInfo.Groups,
			Claims:          claims,
			ExpiresAt:       time.Now().Add(24 * time.Hour), // K8s tokens don't have explicit expiry
			AuthenticatedAt: time.Now(),
		},
		Roles:       []string{},
		Permissions: []Permission{},
	}

	// Apply role bindings
	if v.roleBinder != nil {
		// Add serviceaccount identifier to claims for role binding
		identity.Claims["serviceaccount_id"] = subject

		roles, permissions, err := v.roleBinder.ResolveRoles(identity)
		if err != nil {
			// If no role bindings match, return error
			// This ensures K8s SA tokens must have explicit role bindings
			recordAuthAttempt(ctx, "kubernetes", "failure")
			return nil, err
		}

		identity.Roles = roles
		identity.Permissions = permissions

		// Auto-assign component role for Gibson-managed ServiceAccounts.
		// This is additive — existing role bindings still apply. Non-Gibson SAs
		// are unaffected because deriveComponentRole returns "" for unrecognised names.
		if role, compType, compName := deriveComponentRole(saName); role != "" {
			identity.Roles = append(identity.Roles, role)
			identity.Claims["gibson.io/type"] = compType
			identity.Claims["gibson.io/name"] = compName
		}

		// Capabilities are no longer derived from roles — the
		// declarative-rbac-framework interceptor authorizes via Casbin
		// using roles loaded from permissions.yaml at startup.
		identity.Capabilities = nil
	}

	recordAuthAttempt(ctx, "kubernetes", "success")
	return identity, nil
}

// ensureClient initializes the Kubernetes client if not already initialized.
//
// Uses sync.Once to ensure initialization happens exactly once, even with
// concurrent calls. Initialization errors are cached and returned on every call.
func (v *K8sValidator) ensureClient() error {
	v.clientOnce.Do(func() {
		var config *rest.Config
		var err error

		// Try kubeconfig path first if configured
		if v.config.KubeconfigPath != "" {
			config, err = clientcmd.BuildConfigFromFlags("", v.config.KubeconfigPath)
			if err != nil {
				v.clientErr = fmt.Errorf("failed to load kubeconfig from %s: %w", v.config.KubeconfigPath, err)
				return
			}
		} else {
			// Use in-cluster config
			config, err = rest.InClusterConfig()
			if err != nil {
				v.clientErr = fmt.Errorf("failed to load in-cluster config: %w", err)
				return
			}
		}

		// Create clientset
		v.client, v.clientErr = kubernetes.NewForConfig(config)
	})

	return v.clientErr
}

// parseServiceAccountUsername extracts namespace and name from K8s SA username.
//
// Expected format: system:serviceaccount:<namespace>:<name>
// Example: system:serviceaccount:ci-cd:security-scanner
//
// Returns namespace, serviceaccount name, and error if format is invalid.
func parseServiceAccountUsername(username string) (namespace, name string, err error) {
	const prefix = "system:serviceaccount:"
	if len(username) < len(prefix) {
		return "", "", fmt.Errorf("username too short: %s", username)
	}

	if username[:len(prefix)] != prefix {
		return "", "", fmt.Errorf("username does not start with %s: %s", prefix, username)
	}

	// Remove prefix
	remainder := username[len(prefix):]

	// Split by colon
	var parts []string
	start := 0
	for i := 0; i < len(remainder); i++ {
		if remainder[i] == ':' {
			parts = append(parts, remainder[start:i])
			start = i + 1
		}
	}
	// Add last part
	if start < len(remainder) {
		parts = append(parts, remainder[start:])
	}

	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected namespace:name after prefix, got %d parts: %s", len(parts), remainder)
	}

	namespace = parts[0]
	name = parts[1]

	if namespace == "" || name == "" {
		return "", "", fmt.Errorf("namespace or name is empty: %s", username)
	}

	return namespace, name, nil
}

// deriveComponentRole returns the Gibson component role for a ServiceAccount
// name following the gibson-{type}-{name} convention. Returns empty string
// if the SA name does not match a known component pattern.
func deriveComponentRole(saName string) (role, compType, compName string) {
	prefixes := map[string]string{
		"gibson-tool-":   "tool-executor",
		"gibson-agent-":  "agent-executor",
		"gibson-plugin-": "plugin-executor",
	}
	for prefix, r := range prefixes {
		if strings.HasPrefix(saName, prefix) {
			name := strings.TrimPrefix(saName, prefix)
			typ := strings.TrimPrefix(prefix, "gibson-")
			typ = strings.TrimSuffix(typ, "-")
			return r, typ, name
		}
	}
	return "", "", ""
}
