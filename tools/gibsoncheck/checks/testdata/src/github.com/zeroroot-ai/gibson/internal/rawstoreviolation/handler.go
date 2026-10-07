// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package rawstoreviolation

import (
	_ "github.com/jackc/pgx/v5"      // want `forbidden import "github.com/jackc/pgx/v5"`
	_ "github.com/redis/go-redis/v9" // want `forbidden import "github.com/redis/go-redis/v9"`
)
