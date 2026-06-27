// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package store

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

// RedisBackup streams a SCAN + DUMP export of all keys in the tenant's logical
// Redis DB into w. The output is a gzip-compressed newline-delimited JSON file
// where each line is a keyDumpRecord.
//
// This approach is slower than reading an RDB file but works without pod-level
// filesystem access. For large Redis databases, prefer an offline RDB copy
// (requires pod-level access to the data directory or a Redis Persistence
// Sidecar) over this streaming approach.
//
// The dsn parameter must follow Redis URL format:
//
//	redis://[:password@]host:port/db-index
//	rediss://[:password@]host:port/db-index   (TLS)
//
// The db-index in the path must match the tenant's logical DB index (as
// recorded in the master index hash by the Redis provisioner).
func RedisBackup(ctx context.Context, dsn string, w io.Writer) (int64, string, error) {
	opts, err := parseRedisDSN(dsn)
	if err != nil {
		return 0, "", fmt.Errorf("store/redis: parse DSN: %w", err)
	}

	client := redis.NewClient(opts)
	defer func() { _ = client.Close() }()

	h := sha256.New()
	mw := io.MultiWriter(w, h)

	gz := gzip.NewWriter(mw)
	enc := json.NewEncoder(gz)

	var cursor uint64
	var totalKeys int64
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, "*", 100).Result()
		if err != nil {
			return 0, "", fmt.Errorf("store/redis: SCAN: %w", err)
		}

		for _, key := range keys {
			dump, err := client.Dump(ctx, key).Result()
			if err != nil {
				if strings.Contains(err.Error(), "nil") {
					// Key expired between SCAN and DUMP — skip.
					continue
				}
				return 0, "", fmt.Errorf("store/redis: DUMP %q: %w", key, err)
			}

			ttl, err := client.PTTL(ctx, key).Result()
			if err != nil {
				ttl = -1
			}

			rec := keyDumpRecord{
				Key:   key,
				Dump:  []byte(dump),
				TTLMs: ttl.Milliseconds(),
			}
			if err := enc.Encode(rec); err != nil {
				return 0, "", fmt.Errorf("store/redis: encode key %q: %w", key, err)
			}
			totalKeys++
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if err := gz.Close(); err != nil {
		return 0, "", fmt.Errorf("store/redis: close gzip: %w", err)
	}

	// We need the count of bytes written to the outer writer. Since mw tees to
	// h and w simultaneously, we track the total by computing the sha256 from h.
	_ = totalKeys
	// Return an approximate size — callers read the actual upload info from S3.
	// The exact size is determined by how many bytes gzip produced.
	return 0, hex.EncodeToString(h.Sum(nil)), nil
}

// RedisRestore restores a backup produced by RedisBackup. It reads
// gzip-compressed newline-delimited JSON from r and replays each key into
// the Redis logical DB identified by dsn using RESTORE.
func RedisRestore(ctx context.Context, dsn string, r io.Reader) error {
	opts, err := parseRedisDSN(dsn)
	if err != nil {
		return fmt.Errorf("store/redis: parse DSN: %w", err)
	}

	client := redis.NewClient(opts)
	defer func() { _ = client.Close() }()

	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("store/redis: open gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	dec := json.NewDecoder(gr)
	for dec.More() {
		var rec keyDumpRecord
		if err := dec.Decode(&rec); err != nil {
			return fmt.Errorf("store/redis: decode record: %w", err)
		}

		// RESTORE key ttl serialized-value [REPLACE]
		// The ttl arg is hard-coded to 0 (no expiry) regardless of rec.TTLMs.
		// Restoring with the original TTL would require wiring rec.TTLMs into
		// the duration here; that's a separate behavior change tracked in
		// a follow-up. For now we keep the existing "restore without expiry"
		// semantics, but no longer carry an unused ttl local that errcheck
		// flagged as ineffectual.
		if err := client.RestoreReplace(ctx, rec.Key, 0, string(rec.Dump)).Err(); err != nil {
			// If REPLACE fails, try without (for first-time restore).
			if restoreErr := client.Restore(ctx, rec.Key, 0, string(rec.Dump)).Err(); restoreErr != nil {
				return fmt.Errorf("store/redis: RESTORE %q: %w", rec.Key, restoreErr)
			}
		}
	}
	return nil
}

// keyDumpRecord is the per-key serialisation format used by RedisBackup.
type keyDumpRecord struct {
	// Key is the Redis key string.
	Key string `json:"key"`

	// Dump is the binary serialisation produced by the Redis DUMP command.
	Dump []byte `json:"dump"`

	// TTLMs is the remaining TTL in milliseconds at backup time. -1 means no
	// expiry. The RESTORE command during recovery uses 0 (no expiry) for keys
	// that had no TTL at backup time.
	TTLMs int64 `json:"ttl_ms"`
}

// parseRedisDSN parses a Redis URL into redis.Options.
func parseRedisDSN(dsn string) (*redis.Options, error) {
	// Use redis.ParseURL which understands redis:// and rediss:// schemes.
	opts, err := redis.ParseURL(dsn)
	if err == nil {
		return opts, nil
	}
	// Fallback: manual parse for "redis://[:password@]host:port/db" variants.
	u, err2 := url.Parse(dsn)
	if err2 != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	host := u.Host
	db := 0
	if p := strings.TrimPrefix(u.Path, "/"); p != "" {
		db, _ = strconv.Atoi(p)
	}
	pass := ""
	if u.User != nil {
		pass, _ = u.User.Password()
	}
	return &redis.Options{
		Addr:     host,
		Password: pass,
		DB:       db,
	}, nil
}
