package awssm

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// staticCredentials is a simple aws.CredentialsProvider backed by a static
// access key and secret. Used for AuthMethodStatic (development only).
type staticCredentials struct {
	accessKeyID     string
	secretAccessKey string
}

// newStaticCredentials constructs a staticCredentials provider.
func newStaticCredentials(accessKeyID, secretAccessKey string) *staticCredentials {
	return &staticCredentials{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
	}
}

// Retrieve returns the static credentials. The credentials never expire.
func (s *staticCredentials) Retrieve(_ context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     s.accessKeyID,
		SecretAccessKey: s.secretAccessKey,
		Source:          "awssm.staticCredentials",
	}, nil
}
