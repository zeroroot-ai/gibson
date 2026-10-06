// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// The variables of the export. The chart sets them from the durable bucket
// of the install (ADR-0083). On prem, they name the S3-compatible store of
// the customer.
const (
	// ExportEndpointEnv is the URL of the store, for example
	// https://s3.us-east-1.amazonaws.com or http://minio.minio:9000.
	ExportEndpointEnv = "GIBSON_AUDIT_EXPORT_ENDPOINT"
	// ExportBucketEnv is the bucket name.
	ExportBucketEnv = "GIBSON_AUDIT_EXPORT_BUCKET"
	// ExportRegionEnv is the region of the bucket. Empty gives us-east-1.
	ExportRegionEnv = "GIBSON_AUDIT_EXPORT_REGION"
	// ExportAccessKeyEnv and ExportSecretKeyEnv are the credential.
	ExportAccessKeyEnv = "GIBSON_AUDIT_EXPORT_ACCESS_KEY_ID"
	ExportSecretKeyEnv = "GIBSON_AUDIT_EXPORT_SECRET_ACCESS_KEY" //nolint:gosec // G101: the name of a variable, not a credential
	// ExportLockModeEnv is GOVERNANCE or COMPLIANCE. It must match the
	// bucket policy.
	ExportLockModeEnv = "GIBSON_AUDIT_EXPORT_LOCK_MODE"
	// ExportLockDaysEnv is the lock period in days. It must be at least the
	// period that the bucket policy requires.
	ExportLockDaysEnv = "GIBSON_AUDIT_EXPORT_LOCK_DAYS"
)

// ErrExportNotConfigured is returned by ExportConfigFromEnv when no
// variable of the export is set.
var ErrExportNotConfigured = errors.New("audit export: no store is configured (" + ExportBucketEnv + " is empty)")

// ExportConfig is the store and the lock policy of the export.
type ExportConfig struct {
	Endpoint  *url.URL
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Policy    ExportPolicy
}

// ExportConfigFromEnv reads the export config. It returns
// ErrExportNotConfigured when the bucket variable is empty, and an error
// for each other missing or bad value.
func ExportConfigFromEnv() (ExportConfig, error) {
	get := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	bucket := get(ExportBucketEnv)
	if bucket == "" {
		return ExportConfig{}, ErrExportNotConfigured
	}
	cfg := ExportConfig{
		Bucket:    bucket,
		Region:    get(ExportRegionEnv),
		AccessKey: get(ExportAccessKeyEnv),
		SecretKey: get(ExportSecretKeyEnv),
		Policy:    ExportPolicy{LockMode: strings.ToUpper(get(ExportLockModeEnv))},
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	raw := get(ExportEndpointEnv)
	if raw == "" {
		return ExportConfig{}, fmt.Errorf("audit export: %s is required", ExportEndpointEnv)
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return ExportConfig{}, fmt.Errorf("audit export: %s=%q is not an http or https URL", ExportEndpointEnv, raw)
	}
	cfg.Endpoint = endpoint
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return ExportConfig{}, fmt.Errorf("audit export: %s and %s are required", ExportAccessKeyEnv, ExportSecretKeyEnv)
	}
	days, err := strconv.Atoi(get(ExportLockDaysEnv))
	if err != nil {
		return ExportConfig{}, fmt.Errorf("audit export: %s is not a number of days: %w", ExportLockDaysEnv, err)
	}
	cfg.Policy.LockDays = days
	if err := cfg.Policy.Validate(); err != nil {
		return ExportConfig{}, err
	}
	return cfg, nil
}

// S3Store writes exported objects to an S3-compatible bucket.
type S3Store struct {
	client *minio.Client
	bucket string
}

var _ ObjectStore = (*S3Store)(nil)

// NewS3Store returns the store of cfg. It opens no connection.
func NewS3Store(cfg ExportConfig) (*S3Store, error) {
	if cfg.Endpoint == nil || cfg.Bucket == "" {
		return nil, errors.New("audit.NewS3Store: endpoint and bucket are required")
	}
	client, err := minio.New(cfg.Endpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.Endpoint.Scheme == "https",
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("audit.NewS3Store: %w", err)
	}
	return &S3Store{client: client, bucket: cfg.Bucket}, nil
}

// PutLocked writes one object with the given object lock.
func (s *S3Store) PutLocked(ctx context.Context, key string, body []byte, lock ObjectLock) error {
	mode := minio.Governance
	if lock.Mode == LockModeCompliance {
		mode = minio.Compliance
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
		ContentType:     "application/x-ndjson",
		Mode:            mode,
		RetainUntilDate: lock.RetainUntil,
		SendContentMd5:  true,
	})
	if err != nil {
		return fmt.Errorf("audit: put %s: %w", key, err)
	}
	return nil
}
