/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// kek_kms.go: AWS KMS-backed KEKDeriver implementation.
//
// Spec: helm-eks-readiness-and-pg-split Phase 5 (T5.1).
//
// Production EKS deployments select this deriver when GIBSON_KMS_KEY_ARN
// is set (cmd/main.go and cmd/backfill-credentials/main.go select-and-fall-
// through chain). The plaintext master KEK never enters the operator
// process memory; KMS performs the HMAC operation server-side.
//
// Mechanism: AWS KMS GenerateMac with HMAC_SHA_256 over the tenant ID
// produces a deterministic 32-byte output for a given (key, tenantID)
// pair, which we adopt as the per-tenant KEK. The KMS key MUST be of
// type HMAC_SHA_256 (not the default symmetric encryption key); the
// Terraform skeleton (terraform/eks/main.tf) creates an HMAC key.

package dataplane

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	gtenant "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
	"github.com/zeroroot-ai/sdk/auth"
)

// KMSHMACAPI is the subset of *kms.Client this deriver consumes. Lifted
// to an interface for testability with kmsmock.
type KMSHMACAPI interface {
	GenerateMac(ctx context.Context, in *kms.GenerateMacInput, optFns ...func(*kms.Options)) (*kms.GenerateMacOutput, error)
}

// kmsHMACDeriver derives per-tenant KEKs via KMS GenerateMac. The KMS
// key MUST be HMAC_SHA_256.
type kmsHMACDeriver struct {
	client KMSHMACAPI
	keyID  string // KMS key ARN or alias
}

// NewKMSHMACDeriver constructs a KEKDeriver that calls KMS GenerateMac
// with HMAC_SHA_256 against keyID. Returns an error when keyID is empty
// or client is nil; the chart's Phase 7 values-eks.yaml supplies the
// key ARN via GIBSON_KMS_KEY_ARN.
func NewKMSHMACDeriver(client KMSHMACAPI, keyID string) (KEKDeriver, error) {
	if client == nil {
		return nil, fmt.Errorf("dataplane/kek: KMS client required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("dataplane/kek: KMS key ID required (set GIBSON_KMS_KEY_ARN)")
	}
	return &kmsHMACDeriver{client: client, keyID: keyID}, nil
}

// DeriveTenantKEK calls KMS GenerateMac(HMAC_SHA_256, msg=tenantID).
// Output is 32 bytes (matches gtenant.KEKLength) and deterministic for
// a given (keyID, tenantID) pair — the same property Vault transit HMAC
// provides. Caller zeroizes.
func (d *kmsHMACDeriver) DeriveTenantKEK(ctx context.Context, tenantID auth.TenantID) ([]byte, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("dataplane/kek: cannot derive KEK for zero TenantID")
	}

	out, err := d.client.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId:        &d.keyID,
		Message:      []byte(tenantID.String()),
		MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("dataplane/kek: KMS GenerateMac: %w", err)
	}
	if len(out.Mac) != gtenant.KEKLength {
		return nil, fmt.Errorf("dataplane/kek: KMS returned %d-byte MAC, expected %d",
			len(out.Mac), gtenant.KEKLength)
	}

	// Defensive copy so the AWS SDK's response struct can be GC'd
	// without leaving the KEK in its buffer.
	kek := make([]byte, gtenant.KEKLength)
	copy(kek, out.Mac)
	return kek, nil
}
