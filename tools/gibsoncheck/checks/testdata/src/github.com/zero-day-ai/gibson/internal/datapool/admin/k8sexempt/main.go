package k8sexempt

// Exempt fixture for NoK8sAPIInDaemonAnalyzer. Paths containing
// /internal/datapool/admin/ are allowlisted because admin enumeration
// is legitimate behind the adminpoolacquire gate. No diagnostic
// expected even though the file imports k8s.io/client-go.

import (
	_ "k8s.io/client-go/kubernetes"
)
