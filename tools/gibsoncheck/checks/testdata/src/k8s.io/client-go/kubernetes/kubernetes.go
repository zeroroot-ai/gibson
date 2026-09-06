// Package kubernetes is a stub for the K8s typed clientset, used by
// analysistest fixtures that need to import the forbidden path.
package kubernetes

// Interface is a stand-in for kubernetes.Interface. Test fixtures may
// reference it to exercise the deny-list rule.
type Interface interface {
	Stub()
}
