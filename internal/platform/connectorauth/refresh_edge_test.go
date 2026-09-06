// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package connectorauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// notFoundStore wraps the fake broker but answers Resolve with a gRPC
// NotFound status, the shape the real secrets service returns for an absent
// name.
type notFoundStore struct{ *fakeStore }

func (n notFoundStore) Resolve(ctx context.Context, name string) ([]byte, error) {
	if _, err := n.fakeStore.Resolve(ctx, name); err != nil {
		return nil, status.Errorf(codes.NotFound, "secret %q not found", name)
	}
	return n.fakeStore.Resolve(ctx, name)
}

// An absent grant is a normal state — a registered connector nobody has
// authorized yet — and the refresher loop needs to tell it apart from a
// broken one without string matching.
func TestRefresh_AbsentGrantIsErrNoGrant(t *testing.T) {
	r, _ := NewRefresher(notFoundStore{newStore()}, nil, nil)
	_, err := r.Refresh(context.Background(), "gitlab")
	if !errors.Is(err, ErrNoGrant) {
		t.Fatalf("want ErrNoGrant, got %v", err)
	}
}

// A broker failure that is not NotFound must NOT read as "no grant": the loop
// would silently stop refreshing a connector whose grant still exists.
func TestRefresh_BrokerFailureIsNotErrNoGrant(t *testing.T) {
	r, _ := NewRefresher(newStore(), nil, nil) // fake returns a plain error
	_, err := r.Refresh(context.Background(), "gitlab")
	if err == nil || errors.Is(err, ErrNoGrant) {
		t.Fatalf("a non-NotFound resolve failure must stay an error, got %v", err)
	}
}

// If the expiry metadata cannot be written the refresh fails loudly; the next
// pass re-refreshes because a token without metadata reads as half-written.
func TestRefresh_FailsWhenExpiryMetadataCannotBeWritten(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, false)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")
	s.putErr[AccessMetaSecretName("gitlab")] = errors.New("broker down")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("an unwritable expiry metadata must fail the refresh")
	}
	if !r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("the half-written state must still need refresh")
	}
}

func TestStatusBook_RecordsAndClears(t *testing.T) {
	b := NewStatusBook()
	at := time.Unix(1_700_000_000, 0).UTC()

	if _, ok := b.Get("t1", "gitlab"); ok {
		t.Fatal("empty book must report nothing")
	}
	b.Record("t1", "gitlab", errors.New("invalid_grant"), at)
	st, ok := b.Get("t1", "gitlab")
	if !ok || st.LastError != "invalid_grant" || !st.LastAttempt.Equal(at) {
		t.Fatalf("recorded failure = %+v ok=%v", st, ok)
	}
	b.Record("t1", "gitlab", nil, at.Add(time.Minute))
	st, _ = b.Get("t1", "gitlab")
	if st.LastError != "" {
		t.Errorf("a success must clear the error, got %q", st.LastError)
	}
	if _, ok := b.Get("t2", "gitlab"); ok {
		t.Error("records must be tenant-scoped")
	}
	b.Clear("t1", "gitlab")
	if _, ok := b.Get("t1", "gitlab"); ok {
		t.Error("Clear must remove the record")
	}
}

func TestNewRefresher_RequiresAStore(t *testing.T) {
	if _, err := NewRefresher(nil, nil, nil); err == nil {
		t.Fatal("a refresher with no store must be refused")
	}
}

func TestRefresh_MissingGrantIsNamed(t *testing.T) {
	r, _ := NewRefresher(newStore(), nil, nil)
	_, err := r.Refresh(context.Background(), "gitlab")
	if err == nil {
		t.Fatal("a connector with no grant must fail")
	}
	// The operator's next action is to authorize the connector, so the error
	// has to say which secret is absent.
	if !strings.Contains(err.Error(), GrantSecretName("gitlab")) {
		t.Errorf("error should name the grant secret, got %v", err)
	}
}

func TestRefresh_UnreachableEndpointDoesNotLeakTheURL(t *testing.T) {
	s := newStore()
	// A port nothing listens on: the transport error is the interesting path.
	seedGrant(t, s, "gitlab", "http://127.0.0.1:1/oauth/token", "rt-1")
	r, _ := NewRefresher(s, &http.Client{}, nil)

	_, err := r.Refresh(context.Background(), "gitlab")
	if err == nil {
		t.Fatal("an unreachable token endpoint must be an error")
	}
	// The endpoint is not itself a credential, but repeating it on every retry
	// puts a customer's internal hostname in our logs for no benefit.
	if strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error should name the connector, not the endpoint: %v", err)
	}
}

func TestRefresh_NonJSONResponseIsRefused(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>proxy error</html>"))
	}))
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("a non-JSON 200 must be refused rather than parsed as a token")
	}
}

// A 200 carrying no access_token is a broken vendor, not a success.
func TestRefresh_EmptyAccessTokenIsRefused(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"expires_in":3600}`))
	}))
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("a response with no access_token must be refused")
	}
	if s.get(AccessSecretName("gitlab")) != nil {
		t.Error("nothing may be published when the vendor returned no token")
	}
}

// A vendor that omits expires_in has not said the token is eternal.
func TestRefresh_MissingExpiresInGetsABoundedLifetime(t *testing.T) {
	s := newStore()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1"}`))
	}))
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")

	r, _ := NewRefresher(s, srv.Client(), nil)
	tok, err := r.Refresh(context.Background(), "gitlab")
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("a token with no stated expiry must still get one, or the refresher pins it forever")
	}
}

// If the access token cannot be published, the refresh fails loudly. A caller
// that got no error would assume the connector can authenticate.
func TestRefresh_FailsWhenAccessTokenCannotBePublished(t *testing.T) {
	s := newStore()
	srv := tokenServer(t, false)
	defer srv.Close()
	seedGrant(t, s, "gitlab", srv.URL, "rt-1")
	s.putErr[AccessSecretName("gitlab")] = errors.New("broker down")

	r, _ := NewRefresher(s, srv.Client(), nil)
	if _, err := r.Refresh(context.Background(), "gitlab"); err == nil {
		t.Fatal("an unpublishable access token must fail the refresh")
	}
}

func TestEnsureFresh_SurfacesARefreshFailure(t *testing.T) {
	s := newStore() // no grant seeded
	r, _ := NewRefresher(s, nil, nil)
	did, err := r.EnsureFresh(context.Background(), "gitlab")
	if err == nil {
		t.Fatal("EnsureFresh must surface a refresh failure")
	}
	if did {
		t.Error("a failed refresh must not report that it refreshed")
	}
}

// A nil StatusBook is legal everywhere — recording into nothing is a no-op,
// reading yields nothing.
func TestStatusBook_NilReceiverIsSafe(t *testing.T) {
	var b *StatusBook
	b.Record("t1", "gitlab", nil, time.Unix(1_700_000_000, 0).UTC())
	if _, ok := b.Get("t1", "gitlab"); ok {
		t.Error("a nil book holds nothing")
	}
	b.Clear("t1", "gitlab")
}

// WithSkew ignores a non-positive duration rather than disabling the window.
func TestWithSkew_IgnoresNonPositive(t *testing.T) {
	s := newStore()
	now := time.Unix(1_700_000_000, 0).UTC()
	r, _ := NewRefresher(s, nil, func() time.Time { return now }, WithSkew(0))
	_ = s.Put(context.Background(), AccessSecretName("gitlab"), []byte("at-1"))
	meta := []byte(`{"access_token":"at-1","expires_at":"2023-11-14T22:53:20Z"}`) // now+40m
	_ = s.Put(context.Background(), AccessMetaSecretName("gitlab"), meta)
	if r.NeedsRefresh(context.Background(), "gitlab") {
		t.Error("the default 60s skew must survive WithSkew(0)")
	}
}
