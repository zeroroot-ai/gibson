// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon is a fixture of the forbidredisclientconstruction analyzer.
// This file is named in redisClientConstructionFiles, so its call is allowed.
package daemon

import (
	goredis "github.com/redis/go-redis/v9"
)

func queueClient() *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})
}
