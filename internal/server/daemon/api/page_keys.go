// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// pageOf checks the token of a request. list names the list, with the service
// as prefix, and so the key. The scope of the token holds the tenant, the list
// and each filter that changes the list or its order. A token that the daemon
// did not sign for this scope gives InvalidArgument.
func pageOf(
	keys *pagetoken.Keys, list string, size int32, token, tenantID string, filters ...string,
) (pagetoken.Request, error) {
	if keys == nil {
		return pagetoken.Request{}, status.Error(codes.Internal, "page tokens are not configured")
	}
	signer, err := keys.Signer(list)
	if err != nil {
		return pagetoken.Request{}, pageTokenStatus(err)
	}
	req, err := pagetoken.NewRequest(signer, append([]string{tenantID, list}, filters...), size, token)
	if err != nil {
		return pagetoken.Request{}, pageTokenStatus(err)
	}
	return req, nil
}

// pageTokenStatus maps an error of the page token code to a gRPC status. A
// token that is not valid for the query is the caller's mistake.
func pageTokenStatus(err error) error {
	if errors.Is(err, pagetoken.ErrBadToken) {
		return status.Error(codes.InvalidArgument, pagetoken.ErrBadToken.Error())
	}
	return status.Errorf(codes.Internal, "page token: %v", err)
}
