// Package redisclientviolation contains a synthetic violation of the
// redis.NewClient construction rule. This fixture is used by the
// forbidredisclientconstruction analyzer's test suite.
package redisclientviolation

import (
	goredis "github.com/redis/go-redis/v9"
)

// badInit constructs a redis.Client directly outside the allowlisted packages.
func badInit() *goredis.Client {
	return goredis.NewClient(&goredis.Options{ // want `forbidden call to redis.NewClient`
		Addr: "localhost:6379",
	})
}
