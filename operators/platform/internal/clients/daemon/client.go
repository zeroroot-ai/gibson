/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package daemon provides a gRPC client stub for the daemon's
// gibson.daemon.operator.v1.DaemonOperatorService. The service was renamed
// from PlatformOperatorService in platform-sdk v0.8.0 (ADR-0037).
//
// The transport layer (SPIFFE-mTLS dial) is the caller's responsibility;
// this package exposes a constructor that wraps any grpc.ClientConnInterface.
package daemon

import (
	"google.golang.org/grpc"

	operatorv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/daemon/operator/v1"
)

// NewDaemonOperatorClient wraps conn in a DaemonOperatorServiceClient.
// Callers supply the gRPC connection (e.g. a SPIFFE-mTLS *grpc.ClientConn
// produced by a workloadapi.X509Source transport).
func NewDaemonOperatorClient(conn grpc.ClientConnInterface) operatorv1.DaemonOperatorServiceClient {
	return operatorv1.NewDaemonOperatorServiceClient(conn)
}
