package daemon

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/observability"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// validateNetworkPolicies checks whether NetworkPolicy resources exist in the
// daemon's namespace when running in SaaS mode. This is a warning-only check
// that runs asynchronously after the gRPC server starts.
//
// It does NOT block daemon startup or cause a crash.
func validateNetworkPolicies(logger *observability.Logger, namespace string, isSaaSMode bool) {
	if !isSaaSMode {
		return
	}

	go doValidateNetworkPolicies(logger, namespace, nil)
}

// doValidateNetworkPolicies performs the actual network policy check.
// If clientset is nil, it creates one from in-cluster config.
// Extracted for testability.
func doValidateNetworkPolicies(logger *observability.Logger, namespace string, clientset kubernetes.Interface) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if clientset == nil {
		config, err := rest.InClusterConfig()
		if err != nil {
			logger.Info(ctx, "unable to verify network policies: not running in-cluster",
				"error", err,
			)
			return
		}

		var clientErr error
		clientset, clientErr = kubernetes.NewForConfig(config)
		if clientErr != nil {
			logger.Info(ctx, "unable to verify network policies: failed to create K8s client",
				"error", clientErr,
			)
			return
		}
	}

	policies, err := clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		// RBAC insufficient or API error
		logger.Info(ctx, "unable to verify network policies: insufficient RBAC permissions (list networkpolicies). Skipping check.",
			"namespace", namespace,
			"error", err,
		)
		return
	}

	if len(policies.Items) == 0 {
		logger.Warn(ctx, "SaaS mode enabled but no NetworkPolicy resources found in namespace. Tenant isolation may not be enforced. See documentation for network policy setup.",
			"namespace", namespace,
		)
		return
	}

	logger.Info(ctx, "network policy check passed",
		"namespace", namespace,
		"policy_count", len(policies.Items),
	)
}
