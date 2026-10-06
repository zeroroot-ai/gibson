// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// pageWindow reads the page_size and page_token of a list request
// (ADR-0028, rule 3). A token that the daemon did not write is
// InvalidArgument.
func pageWindow(pageSize int32, pageToken string) (offset, limit int, err error) {
	offset, limit, err = pagetoken.Window(pageSize, pageToken)
	if err != nil {
		return 0, 0, status_grpc.Error(codes.InvalidArgument, err.Error())
	}
	return offset, limit, nil
}
