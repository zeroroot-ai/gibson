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

package store

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/redis/go-redis/v9"
)

// vectorPoint is the NDJSON record format for vector backup/restore.
// Each record represents one Redis hash stored at key vec:<tenant>:<id>.
type vectorPoint struct {
	ID        string            `json:"id"`
	Embedding string            `json:"embedding"` // base64-encoded raw embedding bytes
	Payload   map[string]string `json:"payload,omitempty"`
}

// VectorBackup scans the tenant's Redis vector hash keys and streams them as
// newline-delimited JSON to w. Returns the byte count written and SHA-256
// hex digest of those bytes.
//
// DSN format:
//
//	redis://:password@host:port/db?index=vector_idx:tenant_<underscore_id>
//
// The key prefix is derived by replacing the "vector_idx:" prefix with "vec:"
// and appending ":" — e.g. "vector_idx:tenant_acme" → "vec:tenant_acme:".
func VectorBackup(ctx context.Context, dsn string, w io.Writer) (int64, string, error) {
	client, indexName, err := parseVectorDSN(dsn)
	if err != nil {
		return 0, "", fmt.Errorf("store/vector: parse DSN: %w", err)
	}
	defer func() { _ = client.Close() }()

	keyPrefix := indexToKeyPrefix(indexName)
	h := sha256.New()
	mw := io.MultiWriter(w, h)
	var total int64

	var cursor uint64
	for {
		var keys []string
		var nextCursor uint64
		keys, nextCursor, err = client.Scan(ctx, cursor, keyPrefix+"*", 100).Result()
		if err != nil {
			return 0, "", fmt.Errorf("store/vector: SCAN: %w", err)
		}

		for _, key := range keys {
			fields, hErr := client.HGetAll(ctx, key).Result()
			if hErr != nil {
				return 0, "", fmt.Errorf("store/vector: HGETALL %s: %w", key, hErr)
			}

			id := strings.TrimPrefix(key, keyPrefix)

			embRaw := fields["embedding"]
			delete(fields, "embedding")

			point := vectorPoint{
				ID:        id,
				Embedding: base64.StdEncoding.EncodeToString([]byte(embRaw)),
				Payload:   fields,
			}
			if len(point.Payload) == 0 {
				point.Payload = nil
			}

			line, mErr := json.Marshal(point)
			if mErr != nil {
				return 0, "", fmt.Errorf("store/vector: marshal point %s: %w", id, mErr)
			}
			line = append(line, '\n')

			n, wErr := mw.Write(line)
			total += int64(n)
			if wErr != nil {
				return 0, "", fmt.Errorf("store/vector: write: %w", wErr)
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return total, hex.EncodeToString(h.Sum(nil)), nil
}

// VectorRestore reads NDJSON lines from r and restores vector hash keys into
// the tenant's Redis DB using pipelined HSET commands.
//
// DSN format: see VectorBackup.
func VectorRestore(ctx context.Context, dsn string, r io.Reader) error {
	client, indexName, err := parseVectorDSN(dsn)
	if err != nil {
		return fmt.Errorf("store/vector: parse DSN: %w", err)
	}
	defer func() { _ = client.Close() }()

	keyPrefix := indexToKeyPrefix(indexName)

	scanner := bufio.NewScanner(r)
	// Allow lines up to 16 MiB to handle large embeddings.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	var batch []vectorPoint
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var p vectorPoint
		if err := json.Unmarshal(line, &p); err != nil {
			return fmt.Errorf("store/vector: unmarshal line: %w", err)
		}
		batch = append(batch, p)
		if len(batch) >= 100 {
			if err := writeBatch(ctx, client, keyPrefix, batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("store/vector: scan: %w", err)
	}
	if len(batch) > 0 {
		return writeBatch(ctx, client, keyPrefix, batch)
	}
	return nil
}

// writeBatch writes a slice of vectorPoints into Redis via a single pipeline.
func writeBatch(ctx context.Context, client *redis.Client, keyPrefix string, batch []vectorPoint) error {
	pipe := client.Pipeline()
	for _, p := range batch {
		key := keyPrefix + p.ID

		embBytes, err := base64.StdEncoding.DecodeString(p.Embedding)
		if err != nil {
			return fmt.Errorf("store/vector: decode embedding for %s: %w", p.ID, err)
		}

		// Build the HSET field list: embedding first, then payload fields.
		fields := make([]any, 0, 2+len(p.Payload)*2)
		fields = append(fields, "embedding", string(embBytes))
		for k, v := range p.Payload {
			fields = append(fields, k, v)
		}

		pipe.HSet(ctx, key, fields...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store/vector: pipeline exec: %w", err)
	}
	return nil
}

// parseVectorDSN parses a Redis vector backup DSN and returns a client plus
// the index name extracted from the ?index= query parameter.
//
// The ?index= parameter is stripped before passing the URL to redis.ParseURL
// so the standard Redis client does not see unknown query params.
func parseVectorDSN(dsn string) (*redis.Client, string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, "", fmt.Errorf("parse URL: %w", err)
	}

	q := u.Query()
	indexName := q.Get("index")
	if indexName == "" {
		return nil, "", fmt.Errorf("store/vector: DSN must include ?index=<index-name>")
	}

	// Remove the index param before handing to go-redis so it doesn't choke
	// on an unrecognised query parameter.
	q.Del("index")
	u.RawQuery = q.Encode()
	cleanDSN := u.String()

	opt, err := redis.ParseURL(cleanDSN)
	if err != nil {
		return nil, "", fmt.Errorf("parse redis URL: %w", err)
	}

	return redis.NewClient(opt), indexName, nil
}

// indexToKeyPrefix converts an index name to a Redis key prefix.
// "vector_idx:tenant_acme" → "vec:tenant_acme:"
func indexToKeyPrefix(indexName string) string {
	return "vec:" + strings.TrimPrefix(indexName, "vector_idx:") + ":"
}
