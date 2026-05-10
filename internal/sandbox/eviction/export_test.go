package eviction

import "time"

// export_test.go exposes internal state and constructors for use by the
// external test package (eviction_test). This file is compiled only during
// testing (go test includes *_test.go files). Production callers have no
// access to these symbols.

// TestClock is a public interface that mirrors the internal clock interface.
// Tests implement this interface; NewForTest bridges it into the internal
// clock slot.
type TestClock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) (<-chan time.Time, func())
}

// TestConfig is the test-only configuration surface. It mirrors the fields
// of Config that tests need to control, but does not expose production-only
// fields (e.g. KubeClient) that would pull in non-test dependencies.
type TestConfig struct {
	NodeName       string
	Cordonner      NodeCordonner
	Clock          TestClock
	FileExists     func(path string) bool
	OnHealthChange func(HealthState)
}

// NewForTest constructs a Handler from TestConfig. The Handler's watch
// interval is driven by the fake clock's After/NewTicker implementations so
// that Watch() tests do not rely on real tickers.
func NewForTest(tc TestConfig) (*Handler, error) {
	cfg := Config{
		NodeName:       tc.NodeName,
		Cordonner:      tc.Cordonner,
		clock:          tc.Clock,
		onHealthChange: tc.OnHealthChange,
		fileExists:     tc.FileExists,
	}
	return New(cfg)
}
