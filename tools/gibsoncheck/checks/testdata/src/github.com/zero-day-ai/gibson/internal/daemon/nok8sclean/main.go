package nok8sclean

// Clean fixture for NoK8sAPIInDaemonAnalyzer — a daemon package with no
// K8s client imports. The analyzer must emit ZERO diagnostics.

import (
	"context"
	"fmt"
)

// Helper exists so the file isn't empty.
func Helper(ctx context.Context) error {
	return fmt.Errorf("ok")
}
