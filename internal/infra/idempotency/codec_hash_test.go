// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package idempotency

import (
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The fingerprint of the request survives the codec, for a response and for a
// terminal error. An entry from before the field decodes with no fingerprint.
func TestCodec_RequestHashRoundTrips(t *testing.T) {
	any, err := anypb.New(wrapperspb.String("m1"))
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]*CachedResponse{
		"response": {Response: any, RequestHash: "abc"},
		"error":    {TerminalError: &TerminalError{Code: 3, Message: "bad"}, RequestHash: "def"},
	} {
		raw, err := encodeEntry(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := decodeEntry(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out.RequestHash != in.RequestHash {
			t.Errorf("%s: hash = %q, want %q", name, out.RequestHash, in.RequestHash)
		}
	}
	old, err := decodeEntry([]byte(`{"kind":"error","errCode":3,"errMsg":"bad"}`))
	if err != nil || old.RequestHash != "" {
		t.Errorf("an old entry decodes with hash %q, err %v", old.RequestHash, err)
	}
}
