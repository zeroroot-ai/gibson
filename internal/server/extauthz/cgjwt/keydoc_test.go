// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package cgjwt

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc adapts a plain function to http.RoundTripper so fetchKeyDoc's
// transport-level failure paths can be forced deterministically, without a
// flaky real listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// errReader is an io.Reader that always fails, for exercising fetchKeyDoc's
// body-read error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }

func TestFetchKeyDoc_BuildRequestError(t *testing.T) {
	client := &http.Client{}
	// A raw control character in the base URL fails url.Parse inside
	// http.NewRequestWithContext before any request is sent.
	_, err := fetchKeyDoc(context.Background(), client, "http://x\ny", "k1")
	if err == nil {
		t.Fatal("expected a build-request error for a base URL with an invalid control character")
	}
}

func TestFetchKeyDoc_ClientDoError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("simulated transport failure")
	})}
	_, err := fetchKeyDoc(context.Background(), client, "http://daemon.example/keys", "k1")
	if err == nil {
		t.Fatal("expected a transport error to surface")
	}
}

func TestFetchKeyDoc_ReadBodyError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(errReader{}),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := fetchKeyDoc(context.Background(), client, "http://daemon.example/keys", "k1")
	if err == nil {
		t.Fatal("expected a body-read error to surface")
	}
}

func TestFetchKeyDoc_DecodeError(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json")),
			Header:     make(http.Header),
		}, nil
	})}
	_, err := fetchKeyDoc(context.Background(), client, "http://daemon.example/keys", "k1")
	if err == nil {
		t.Fatal("expected a decode error for a non-JSON body")
	}
}

func TestEd25519FromKeyDoc_SkipsMismatchedKid(t *testing.T) {
	pub, _ := mustGenKey(t)
	doc := keyDoc{Keys: []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	}{
		{Kty: "OKP", Crv: "Ed25519", X: "not-the-one", Kid: "other-kid"},
		{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: "k1"},
	}}
	got, err := ed25519FromKeyDoc(doc, "k1")
	if err != nil {
		t.Fatalf("ed25519FromKeyDoc: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("expected the matching-kid key, not the mismatched one")
	}
}

func TestEd25519FromKeyDoc_RejectsBadBase64X(t *testing.T) {
	doc := keyDoc{Keys: []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	}{
		{Kty: "OKP", Crv: "Ed25519", X: "!!!not-base64!!!", Kid: "k1"},
	}}
	if _, err := ed25519FromKeyDoc(doc, "k1"); err == nil {
		t.Fatal("expected rejection of an unparseable x value")
	}
}

func TestEd25519FromKeyDoc_RejectsWrongKeyLength(t *testing.T) {
	doc := keyDoc{Keys: []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Kid string `json:"kid"`
	}{
		{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("too-short")), Kid: "k1"},
	}}
	if _, err := ed25519FromKeyDoc(doc, "k1"); err == nil {
		t.Fatal("expected rejection of a key with the wrong byte length")
	}
}
