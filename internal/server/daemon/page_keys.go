// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
)

// newPageKeys runs once, on one goroutine, at startup.
//
// It builds the page token keys of the daemon and keeps them in d.pageKeys. Every paged service takes its signers from that field, so the
// daemon has one construction. The keys derive from the master KEK, which each
// replica shares, so a token from one replica works on another.
func (d *daemonImpl) newPageKeys(ctx context.Context) (*pagetoken.Keys, error) {
	if d.pageKeys != nil {
		return d.pageKeys, nil
	}
	if d.keyProvider == nil {
		return nil, errors.New("daemon: the page tokens need the key provider")
	}
	masterKEK, err := d.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("daemon: the page tokens could not read the master KEK: %w", err)
	}
	keys, err := pagetoken.NewKeys(masterKEK)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	d.pageKeys = keys
	return keys, nil
}
