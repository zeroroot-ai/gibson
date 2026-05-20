// Package rest stubs k8s.io/client-go/rest for analysistest fixtures.
package rest

// Config is a stand-in for rest.Config.
type Config struct{}

// InClusterConfig is a stand-in.
func InClusterConfig() (*Config, error) { return nil, nil }
