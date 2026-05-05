// Package reservednames reads the chart-managed gibson-reserved-names
// ConfigMap and exposes the (exact, prefix) denylist used by:
//
//   - the dashboard signup form (via PlatformOperatorService.GetReservedNames)
//   - the K8s admission webhook (via the operator's own reader)
//
// Spec: tenant-provisioning-unification-phase2 Requirement 4.5.
package reservednames

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ConfigMapName is the well-known name of the chart-managed denylist
// ConfigMap. It lives in the namespace the daemon pod runs in (see
// LookupNamespace).
const ConfigMapName = "gibson-reserved-names"

// ConfigMap data keys. The chart writes newline-separated entries.
const (
	keyExact  = "exact"
	keyPrefix = "prefix"
)

// LookupNamespace returns the namespace the daemon pod is running in,
// falling back to "gibson" when POD_NAMESPACE is unset (kind dev path).
func LookupNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	if ns := os.Getenv("GIBSON_NAMESPACE"); ns != "" {
		return ns
	}
	return "gibson"
}

// Provider is a 30-second-cached reader for the gibson-reserved-names
// ConfigMap. Safe for concurrent use.
type Provider struct {
	client    kubernetes.Interface
	namespace string
	ttl       time.Duration

	mu       sync.Mutex
	expires  time.Time
	exact    []string
	prefix   []string
	lastErr  error
}

// New constructs a Provider that reads the ConfigMap from the given
// namespace using the supplied K8s client. ttl bounds how stale the
// cached snapshot can be; passing 0 picks 30 seconds.
func New(client kubernetes.Interface, namespace string, ttl time.Duration) *Provider {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Provider{client: client, namespace: namespace, ttl: ttl}
}

// ReservedNames returns the cached (exact, prefix) lists. On a fresh
// cache it issues a single ConfigMap GET; on subsequent calls within
// the TTL it returns the cached snapshot. NotFound is treated as
// "denylist intentionally empty" — not an error.
func (p *Provider) ReservedNames(ctx context.Context) (exact, prefix []string, err error) {
	if p == nil {
		return nil, nil, errors.New("reservednames: nil Provider")
	}
	p.mu.Lock()
	if time.Now().Before(p.expires) {
		exact, prefix, err = p.exact, p.prefix, p.lastErr
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	cm, getErr := p.client.CoreV1().ConfigMaps(p.namespace).Get(ctx, ConfigMapName, metav1.GetOptions{})
	if getErr != nil {
		if apierrors.IsNotFound(getErr) {
			p.store(nil, nil, nil)
			return nil, nil, nil
		}
		// Surface the error this round but cache no result.
		return nil, nil, getErr
	}
	exact = parseList(cm.Data[keyExact])
	prefix = parseList(cm.Data[keyPrefix])
	p.store(exact, prefix, nil)
	return exact, prefix, nil
}

func (p *Provider) store(exact, prefix []string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exact = exact
	p.prefix = prefix
	p.lastErr = err
	p.expires = time.Now().Add(p.ttl)
}

// parseList trims whitespace and skips blank or comment ('#') lines.
func parseList(raw string) []string {
	if raw == "" {
		return nil
	}
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var _ = corev1.ConfigMap{} // keep import explicit for readability
