package rawstoreviolation

import (
	_ "github.com/jackc/pgx/v5"            // want `forbidden import "github.com/jackc/pgx/v5"`
	_ "github.com/redis/go-redis/v9"        // want `forbidden import "github.com/redis/go-redis/v9"`
)
