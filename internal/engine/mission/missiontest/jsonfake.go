// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package missiontest holds test support for code that uses the mission store.
package missiontest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// NewClient returns a Redis client for ConnBoundMissionStore. The store keeps a
// mission with the JSON commands of the RedisJSON module, which miniredis does
// not know. The client answers JSON.SET, JSON.GET and JSON.DEL from a map and
// sends every other command to a miniredis server. It needs no Redis Stack, so a
// test of the creation paths of a mission runs on any machine.
func NewClient(t *testing.T) (*redis.Client, *Docs) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	docs := &Docs{docs: map[string]string{}}
	rdb.AddHook(docs)
	return rdb, docs
}

// Docs holds the JSON documents that the fake keeps.
type Docs struct {
	mu   sync.Mutex
	docs map[string]string
	// FailSet makes each JSON.SET fail, to test the step after a write.
	FailSet bool
}

// Has reports whether a document is stored at key.
func (d *Docs) Has(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.docs[key]
	return ok
}

// Count returns the number of documents.
func (d *Docs) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.docs)
}

// DialHook implements redis.Hook.
func (d *Docs) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}

// ProcessHook implements redis.Hook.
func (d *Docs) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if d.handle(cmd) {
			return cmd.Err()
		}
		return next(ctx, cmd)
	}
}

// ProcessPipelineHook implements redis.Hook.
func (d *Docs) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		var rest []redis.Cmder
		var first error
		for _, c := range cmds {
			if d.handle(c) {
				if first == nil {
					first = c.Err()
				}
				continue
			}
			rest = append(rest, c)
		}
		if len(rest) > 0 {
			if err := next(ctx, rest); err != nil {
				return err
			}
		}
		if first != nil {
			return fmt.Errorf("json fake: %w", first)
		}
		return nil
	}
}

func (d *Docs) handle(cmd redis.Cmder) bool {
	args := cmd.Args()
	if len(args) == 0 {
		return false
	}
	name, _ := args[0].(string)
	if ic, isInt := cmd.(*redis.IntCmd); isInt && strings.EqualFold(name, "EXISTS") && len(args) == 2 {
		// A document that the fake keeps is a key that exists.
		key, _ := args[1].(string)
		d.mu.Lock()
		_, found := d.docs[key]
		d.mu.Unlock()
		if found {
			ic.SetVal(1)
			return true
		}
		return false
	}
	c, ok := cmd.(*redis.Cmd)
	if !ok || !strings.HasPrefix(strings.ToUpper(name), "JSON.") {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key, _ := args[1].(string)
	switch strings.ToUpper(name) {
	case "JSON.SET":
		if d.FailSet {
			c.SetErr(errors.New("json set refused"))
			return true
		}
		val, _ := args[3].(string)
		d.docs[key] = val
		c.SetVal("OK")
	case "JSON.GET":
		v, found := d.docs[key]
		if !found {
			c.SetErr(redis.Nil)
			return true
		}
		c.SetVal("[" + v + "]")
	case "JSON.DEL":
		delete(d.docs, key)
		c.SetVal(int64(1))
	default:
		return false
	}
	return true
}

// Recorder is a mission.TenantRecorder that keeps the tuples as a set. A test
// that creates a mission through a store uses it, because a store that creates a
// mission with no recorder fails.
type Recorder struct {
	mu sync.Mutex
	// Err makes Record fail.
	Err error
	// Tuples holds "<tenant>|<mission id>" for each recorded mission.
	Tuples map[string]bool
	// Forgotten holds the same keys for each Forget.
	Forgotten []string
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{Tuples: map[string]bool{}} }

// Record implements mission.TenantRecorder.
func (r *Recorder) Record(_ context.Context, tenant string, id types.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Err != nil {
		return r.Err
	}
	r.Tuples[tenant+"|"+id.String()] = true
	return nil
}

// Forget implements mission.TenantRecorder.
func (r *Recorder) Forget(_ context.Context, tenant string, id types.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.Tuples, tenant+"|"+id.String())
	r.Forgotten = append(r.Forgotten, tenant+"|"+id.String())
	return nil
}

// Has reports whether the tuple of the mission is recorded.
func (r *Recorder) Has(tenant string, id types.ID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.Tuples[tenant+"|"+id.String()]
}
