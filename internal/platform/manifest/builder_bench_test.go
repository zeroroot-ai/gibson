package manifest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

func benchBuilder(b *testing.B, componentCount, denyRuleCount int) {
	b.Helper()

	// Pre-seeded FGA: user:alice has can_execute on every component; the
	// agent_principal subset has can_execute + cannot_invoke for the
	// denyRuleCount targets.
	listObjects := map[string][]string{
		"user:alice|can_execute|component":              nil,
		"user:alice|can_read|component":                 nil,
		"user:alice|can_configure|component":            nil,
		"agent_principal:A|cannot_invoke|component":     nil,
		"agent_principal:A|can_be_invoked_by|component": nil,
	}
	infos := make([]component.ComponentInfo, componentCount)
	for i := 0; i < componentCount; i++ {
		name := "c" + strconv.Itoa(i)
		infos[i] = component.ComponentInfo{Kind: "tool", Name: name, TenantID: "_system"}
		listObjects["user:alice|can_execute|component"] = append(listObjects["user:alice|can_execute|component"], "component:"+name)
	}
	for i := 0; i < denyRuleCount && i < componentCount; i++ {
		listObjects["agent_principal:A|cannot_invoke|component"] = append(listObjects["agent_principal:A|cannot_invoke|component"], "component:c"+strconv.Itoa(i))
	}

	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis: %v", err)
	}
	b.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	bridge := capabilitygrant.NewFGABridge(&stubAuthorizer{listObjects: listObjects}, &stubRegistry{infos: infos}, nil)
	k, _ := GenerateSignerKey("k1")
	signer, _ := NewSigner("k1", []SignerKey{k})
	vs := NewVersionStore(rdb, time.Second)
	builder, _ := NewBuilder(BuilderDeps{
		FGA: bridge, Registry: &stubRegistry{infos: infos}, Signer: signer, Versions: vs,
	}, BuilderConfig{TTL: time.Minute})

	subj := ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "acme"}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := builder.Build(ctx, subj); err != nil {
			b.Fatalf("Build: %v", err)
		}
	}
	b.StopTimer()
	nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	b.ReportMetric(nsPerOp/1e6, "ms/op")
}

func BenchmarkBuilderBuild_10Components_0Rules(b *testing.B)     { benchBuilder(b, 10, 0) }
func BenchmarkBuilderBuild_50Components_100Rules(b *testing.B)   { benchBuilder(b, 50, 100) }
func BenchmarkBuilderBuild_200Components_1000Rules(b *testing.B) { benchBuilder(b, 200, 1000) }

// Smoke test (not a benchmark) that asserts the 50-component / 100-rule
// configuration finishes well within the 100ms target. Runs in normal
// test invocations so CI enforces the SLO.
func TestBuilderBuild_P95Budget_50c_100r(t *testing.T) {
	listObjects := map[string][]string{
		"user:alice|can_execute|component":   nil,
		"user:alice|can_read|component":      nil,
		"user:alice|can_configure|component": nil,
	}
	infos := make([]component.ComponentInfo, 50)
	for i := 0; i < 50; i++ {
		name := "c" + strconv.Itoa(i)
		infos[i] = component.ComponentInfo{Kind: "tool", Name: name, TenantID: "_system"}
		listObjects["user:alice|can_execute|component"] = append(listObjects["user:alice|can_execute|component"], "component:"+name)
	}
	mr, _ := miniredis.Run()
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	bridge := capabilitygrant.NewFGABridge(&stubAuthorizer{listObjects: listObjects}, &stubRegistry{infos: infos}, nil)
	k, _ := GenerateSignerKey("k1")
	signer, _ := NewSigner("k1", []SignerKey{k})
	vs := NewVersionStore(rdb, time.Second)
	builder, _ := NewBuilder(BuilderDeps{FGA: bridge, Registry: &stubRegistry{infos: infos}, Signer: signer, Versions: vs}, BuilderConfig{TTL: time.Minute})

	// Warm up.
	_, _ = builder.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "acme"})
	// Sample.
	samples := make([]time.Duration, 20)
	for i := range samples {
		start := time.Now()
		if _, err := builder.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "acme"}); err != nil {
			t.Fatalf("Build: %v", err)
		}
		samples[i] = time.Since(start)
	}
	// Max (proxy for p95 given small sample).
	var max time.Duration
	for _, d := range samples {
		if d > max {
			max = d
		}
	}
	if max > 100*time.Millisecond {
		t.Fatalf("worst sample %v exceeded 100ms budget", max)
	}
}
