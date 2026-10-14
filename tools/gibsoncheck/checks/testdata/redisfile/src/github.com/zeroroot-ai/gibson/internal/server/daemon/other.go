// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	goredis "github.com/redis/go-redis/v9"
)

// The file allowlist names one file: another file of the same package is
// still refused.
func otherClient() *goredis.Client {
	return goredis.NewClient(&goredis.Options{Addr: "localhost:6379"}) // want `forbidden call to redis.NewClient`
}
