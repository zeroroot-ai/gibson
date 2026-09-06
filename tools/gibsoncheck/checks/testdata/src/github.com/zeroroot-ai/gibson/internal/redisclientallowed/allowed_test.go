// Package redisclientallowed contains a _test.go file that constructs a
// redis.Client (against miniredis) — this should NOT trigger the analyzer
// because test files are exempt.
package redisclientallowed_test

import (
	goredis "github.com/redis/go-redis/v9"
)

// testHelper is a test-only helper; test files are exempt from the rule.
func testHelper() *goredis.Client {
	return goredis.NewClient(&goredis.Options{ // exempt: _test.go file
		Addr: "localhost:6379",
	})
}
