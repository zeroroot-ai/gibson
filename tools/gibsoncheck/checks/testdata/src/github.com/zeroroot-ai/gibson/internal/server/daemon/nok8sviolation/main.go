package nok8sviolation

// Violation fixture for NoK8sAPIInDaemonAnalyzer. The daemon's internal
// tree must not import any K8s client construction surface per ADR-0023.

import (
	_ "k8s.io/client-go/kubernetes" // want `forbidden import "k8s.io/client-go/kubernetes"`
	_ "k8s.io/client-go/rest"       // want `forbidden import "k8s.io/client-go/rest"`
)
