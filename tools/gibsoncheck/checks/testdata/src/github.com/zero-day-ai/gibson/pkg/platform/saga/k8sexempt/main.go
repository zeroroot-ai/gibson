package k8sexempt

// Exempt fixture. pkg/platform/saga is operator-shared library code;
// the daemon binary does not import it. The rule allow-lists this path
// per ADR-0023 + S11 audit disposition. No diagnostic expected.

import (
	_ "k8s.io/client-go/kubernetes"
)
