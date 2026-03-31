package component

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig holds TLS configuration for gRPC connections
type TLSConfig struct {
	// Enabled enables TLS for connections
	Enabled bool

	// CertFile is the path to the client certificate
	// Required for mTLS (mutual TLS authentication)
	CertFile string

	// KeyFile is the path to the client private key
	// Required for mTLS (mutual TLS authentication)
	KeyFile string

	// CAFile is the path to the CA certificate for server verification
	// If not provided, the system's root CA pool is used
	CAFile string

	// ServerName is the expected server name for verification
	// Used for SNI (Server Name Indication) and certificate verification
	ServerName string

	// InsecureSkipVerify disables server certificate verification
	// WARNING: Only use for development/testing
	// Setting this to true makes the connection vulnerable to man-in-the-middle attacks
	InsecureSkipVerify bool
}

// BuildTLSConfig creates a *tls.Config from the TLSConfig
//
// This method constructs a TLS configuration suitable for use with gRPC
// credentials.NewTLS(). It handles:
//   - Client certificates for mTLS (if CertFile and KeyFile are provided)
//   - Custom CA certificates for server verification (if CAFile is provided)
//   - Server name verification (if ServerName is provided)
//   - Insecure mode for testing (if InsecureSkipVerify is true)
//
// Returns nil if TLS is not enabled.
//
// Example usage:
//
//	tlsConfig := &TLSConfig{
//	    Enabled: true,
//	    CAFile: "/etc/ssl/ca.crt",
//	    ServerName: "grpc.example.com",
//	}
//	tlsCfg, err := tlsConfig.BuildTLSConfig()
//	if err != nil {
//	    return err
//	}
//	creds := credentials.NewTLS(tlsCfg)
//	conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(creds))
func (c *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	// Load client certificate if provided (for mTLS)
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided (for server verification)
	if c.CAFile != "" {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}
