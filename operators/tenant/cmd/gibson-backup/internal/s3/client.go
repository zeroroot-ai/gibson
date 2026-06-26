// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package s3 provides a thin wrapper around minio-go for streaming uploads and
// downloads to S3-compatible object storage (AWS S3, Cloudflare R2, MinIO,
// GCS S3-compat).
//
// Configuration is read from environment variables:
//
//	S3_ENDPOINT   — optional; empty means AWS S3 (path-style for MinIO/R2)
//	S3_BUCKET     — required
//	S3_ACCESS_KEY — required
//	S3_SECRET_KEY — required
//	S3_REGION     — optional; defaults to "us-east-1"
//	S3_USE_SSL    — optional; "false" disables TLS (useful for local MinIO)
package s3

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config holds the S3 connection parameters.
type Config struct {
	// Endpoint is the S3-compatible service endpoint. Leave empty for AWS S3.
	// For MinIO: "localhost:9000". For R2: "<account>.r2.cloudflarestorage.com".
	Endpoint string

	// Bucket is the target S3 bucket name.
	Bucket string

	// AccessKey and SecretKey are the S3 credentials.
	AccessKey string
	SecretKey string

	// Region is the S3 region (e.g. "us-east-1"). Defaults to "us-east-1" if empty.
	Region string

	// UseSSL controls whether TLS is used. Defaults to true.
	UseSSL bool
}

// ConfigFromEnv reads S3 configuration from standard environment variables.
// Returns an error if required variables are absent.
func ConfigFromEnv() (Config, error) {
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		return Config{}, fmt.Errorf("s3: S3_BUCKET environment variable is required")
	}
	accessKey := os.Getenv("S3_ACCESS_KEY")
	if accessKey == "" {
		return Config{}, fmt.Errorf("s3: S3_ACCESS_KEY environment variable is required")
	}
	secretKey := os.Getenv("S3_SECRET_KEY")
	if secretKey == "" {
		return Config{}, fmt.Errorf("s3: S3_SECRET_KEY environment variable is required")
	}

	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	useSSL := true
	if v := os.Getenv("S3_USE_SSL"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("s3: invalid S3_USE_SSL value %q: %w", v, err)
		}
		useSSL = b
	}

	return Config{
		Endpoint:  os.Getenv("S3_ENDPOINT"),
		Bucket:    bucket,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
		UseSSL:    useSSL,
	}, nil
}

// Client wraps a minio.Client and exposes stream-oriented upload and download
// operations against a single bucket.
type Client struct {
	mc     *minio.Client
	bucket string
}

// New constructs a Client from cfg. It does not open a connection; the
// underlying minio client lazily connects on the first operation.
func New(cfg Config) (*Client, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		// AWS S3: minio-go uses the virtual-hosted-style endpoint for AWS by
		// default. The region-specific endpoint ensures bucket-region affinity.
		endpoint = fmt.Sprintf("s3.%s.amazonaws.com", cfg.Region)
	}

	mc, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("s3: create minio client: %w", err)
	}

	return &Client{mc: mc, bucket: cfg.Bucket}, nil
}

// PutObject streams data from r to the object at key. size is the total
// number of bytes to upload; pass -1 if unknown (minio will buffer in memory
// for multipart thresholds). Returns the upload info or an error.
//
// The upload uses the default server-side encryption and storage class. Client-
// side encryption is handled by the caller (see package envelope) before the
// data reaches this function.
func (c *Client) PutObject(ctx context.Context, key string, r io.Reader, size int64) (minio.UploadInfo, error) {
	info, err := c.mc.PutObject(ctx, c.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return minio.UploadInfo{}, fmt.Errorf("s3: put %q: %w", key, err)
	}
	return info, nil
}

// GetObject opens a streaming read of the object at key. The caller is
// responsible for closing the returned ReadCloser.
func (c *Client) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	obj, err := c.mc.GetObject(ctx, c.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("s3: get %q: %w", key, err)
	}
	return obj, nil
}

// ListObjects lists all objects under prefix. The returned slice contains
// object keys (not full URLs).
func (c *Client) ListObjects(ctx context.Context, prefix string) ([]minio.ObjectInfo, error) {
	var infos []minio.ObjectInfo
	for obj := range c.mc.ListObjects(ctx, c.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("s3: list %q: %w", prefix, obj.Err)
		}
		infos = append(infos, obj)
	}
	return infos, nil
}

// StatObject returns metadata for the object at key, or an error if it does
// not exist.
func (c *Client) StatObject(ctx context.Context, key string) (minio.ObjectInfo, error) {
	info, err := c.mc.StatObject(ctx, c.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return minio.ObjectInfo{}, fmt.Errorf("s3: stat %q: %w", key, err)
	}
	return info, nil
}
