package reservednames

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestProvider_NotFound_ReturnsEmpty(t *testing.T) {
	c := fake.NewSimpleClientset()
	p := New(c, "gibson", time.Minute)
	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on NotFound, got %v", err)
	}
	if len(exact) != 0 || len(prefix) != 0 {
		t.Fatalf("expected empty lists, got exact=%v prefix=%v", exact, prefix)
	}
}

func TestProvider_ParsesAndCaches(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName, Namespace: "gibson"},
		Data: map[string]string{
			"exact":  "default\nkube-system\n# a comment\n\ngibson",
			"prefix": "kube-\nsystem-",
		},
	}
	c := fake.NewSimpleClientset(cm)
	p := New(c, "gibson", time.Minute)
	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantExact := []string{"default", "kube-system", "gibson"}
	wantPrefix := []string{"kube-", "system-"}
	if !equal(exact, wantExact) {
		t.Errorf("exact: got %v want %v", exact, wantExact)
	}
	if !equal(prefix, wantPrefix) {
		t.Errorf("prefix: got %v want %v", prefix, wantPrefix)
	}

	if err := c.CoreV1().ConfigMaps("gibson").Delete(context.Background(), ConfigMapName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	exact2, _, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !equal(exact, exact2) {
		t.Errorf("expected cached snapshot to survive delete; got %v", exact2)
	}
}

func TestProvider_TTLExpiry(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName, Namespace: "gibson"},
		Data:       map[string]string{"exact": "alpha"},
	}
	c := fake.NewSimpleClientset(cm)
	p := New(c, "gibson", time.Millisecond) // tiny TTL
	if _, _, err := p.ReservedNames(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	cm2 := cm.DeepCopy()
	cm2.Data["exact"] = "beta"
	if _, err := c.CoreV1().ConfigMaps("gibson").Update(context.Background(), cm2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	exact, _, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !equal(exact, []string{"beta"}) {
		t.Errorf("expected refreshed snapshot, got %v", exact)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
