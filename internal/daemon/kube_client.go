package daemon

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// buildKubeClientForReservedNames returns a typed Kubernetes clientset for
// reading the gibson-reserved-names ConfigMap. Returns (nil, nil) when no
// cluster config is available — dev environments without a cluster.
//
// Spec: tenant-provisioning-unification-phase2 Requirement 4.5.
func buildKubeClientForReservedNames() (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, nil //nolint:nilerr // missing cluster config is normal in dev
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes clientset: %w", err)
	}
	return cs, nil
}
