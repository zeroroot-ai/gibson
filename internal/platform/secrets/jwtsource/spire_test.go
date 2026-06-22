package jwtsource

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// fakeFetcher implements jwtSVIDCloser. It is the lightweight test
// double behind the jwtSVIDCloser seam in SPIREJWTSource — tests inject
// it via the unexported `src` field rather than going through
// NewSPIREJWTSource (which would require a real SPIRE Workload API
// socket). Because the seam is intra-package, no exported test helper
// is required.
type fakeFetcher struct {
	mu     sync.Mutex
	calls  []jwtsvid.Params
	svid   *jwtsvid.SVID
	err    error
	closed bool
}

func (f *fakeFetcher) FetchJWTSVID(_ context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	f.mu.Lock()
	f.calls = append(f.calls, params)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.svid, nil
}

func (f *fakeFetcher) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

// newParsedSVID builds a real *jwtsvid.SVID by signing a JWT with an
// in-memory RSA key and parsing it via jwtsvid.ParseInsecure. The
// resulting SVID has its unexported `token` field populated such that
// Marshal() returns the canonical string — that's how we observe what
// the production SPIREJWTSource hands back from the SPIRE Workload API.
//
// We can't set svid.token from outside the package, so going through
// ParseInsecure is the only construction path. The signer's allowed-alg
// gate (RS256/ES256/...) is the reason we need real signing rather
// than alg=none.
//
// audience is stamped into the aud claim; subject is a SPIRE-shaped
// SPIFFE ID rooted at the "test" trust domain.
func newParsedSVID(t *testing.T, audience string) *jwtsvid.SVID {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: jose.JSONWebKey{
				Key:   key,
				KeyID: "test-kid",
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	claims := jwt.Claims{
		Subject:  "spiffe://test/foo",
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Signed: %v", err)
	}
	svid, err := jwtsvid.ParseInsecure(token, []string{audience})
	if err != nil {
		t.Fatalf("ParseInsecure: %v", err)
	}
	return svid
}

// TestSPIREJWTSource_Token_HappyPath verifies the core seam: Token
// returns the marshaled JWT and passes the audience down to the
// Workload API fetcher unchanged.
func TestSPIREJWTSource_Token_HappyPath(t *testing.T) {
	t.Parallel()
	svid := newParsedSVID(t, "vault-aud")
	fake := &fakeFetcher{svid: svid}
	s := &SPIREJWTSource{src: fake}

	tok, err := s.Token(context.Background(), "vault-aud")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok == "" {
		t.Fatal("Token returned empty string with nil error")
	}
	if tok != svid.Marshal() {
		t.Errorf("Token = %q, want SVID.Marshal() = %q", tok, svid.Marshal())
	}
	if len(fake.calls) != 1 || fake.calls[0].Audience != "vault-aud" {
		t.Errorf("fetcher saw calls=%v, want one call with audience=vault-aud", fake.calls)
	}
}

// TestSPIREJWTSource_Token_PropagatesFetcherError asserts that Workload
// API errors are wrapped with the audience name (so operators can grep)
// but the underlying error remains in the wrap chain.
func TestSPIREJWTSource_Token_PropagatesFetcherError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("spire-agent gone")
	fake := &fakeFetcher{err: wantErr}
	s := &SPIREJWTSource{src: fake}

	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("Token: expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("errors.Is(err, wantErr) = false; got %v", err)
	}
	if !strings.Contains(err.Error(), "vault-aud") {
		t.Errorf("error should name audience for log-grep, got: %v", err)
	}
}

// TestSPIREJWTSource_Token_EmptyAudienceErrors asserts the defensive
// audience-required check (belt-and-suspenders alongside the broker
// init helper's check).
func TestSPIREJWTSource_Token_EmptyAudienceErrors(t *testing.T) {
	t.Parallel()
	fake := &fakeFetcher{svid: newParsedSVID(t, "ignored")}
	s := &SPIREJWTSource{src: fake}

	_, err := s.Token(context.Background(), "")
	if err == nil {
		t.Fatal("Token(empty audience): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("error should name audience, got: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("fetcher was called with empty audience: %v", fake.calls)
	}
}

// TestSPIREJWTSource_Token_NilReceiverSafe guards against the
// "constructor failed and caller forgot to check the error" branch — a
// nil SPIREJWTSource must return a clean error rather than panic.
func TestSPIREJWTSource_Token_NilReceiverSafe(t *testing.T) {
	t.Parallel()
	var s *SPIREJWTSource
	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("Token on nil receiver: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("error should say 'not initialized', got: %v", err)
	}
}

// TestSPIREJWTSource_Close_DelegatesToFetcher asserts the daemon's
// graceful-shutdown chain releases the Workload API connection.
func TestSPIREJWTSource_Close_DelegatesToFetcher(t *testing.T) {
	t.Parallel()
	fake := &fakeFetcher{svid: newParsedSVID(t, "ignored")}
	s := &SPIREJWTSource{src: fake}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fake.closed {
		t.Error("fetcher.Close was not called")
	}
}

// TestSPIREJWTSource_Close_NilReceiverNoop asserts Close on a nil source
// is a no-op (so a failed-constructor + deferred-close path doesn't
// panic the daemon).
func TestSPIREJWTSource_Close_NilReceiverNoop(t *testing.T) {
	t.Parallel()
	var s *SPIREJWTSource
	if err := s.Close(); err != nil {
		t.Fatalf("Close on nil source: %v", err)
	}
}

// TestSPIREJWTSource_SatisfiesJWTSource is a compile-time assertion that
// *SPIREJWTSource satisfies the package's JWTSource interface. Wiring
// in cmd/gibson/main.go relies on this contract.
func TestSPIREJWTSource_SatisfiesJWTSource(t *testing.T) {
	t.Parallel()
	var _ JWTSource = (*SPIREJWTSource)(nil)
}

// TestSPIREJWTSource_Token_RejectsEmptyMarshalledToken asserts the
// defense-in-depth empty-token branch. A real workloadapi.JWTSource
// won't return ("", nil), but a future SDK rev or wrapper might; the
// daemon must surface a clear error rather than stamp an empty JWT
// onto Vault config.
func TestSPIREJWTSource_Token_RejectsEmptyMarshalledToken(t *testing.T) {
	t.Parallel()
	// Build a "valid"-looking SVID whose Marshal() returns empty: the
	// easiest way to do this is to bypass ParseInsecure (which always
	// sets token) and construct an SVID literal — token is unexported,
	// so Marshal() on a zero-value SVID returns "".
	emptySvid := &jwtsvid.SVID{
		ID:       spiffeid.RequireFromString("spiffe://test/foo"),
		Audience: []string{"vault-aud"},
		Expiry:   time.Unix(4070908800, 0),
	}
	fake := &fakeFetcher{svid: emptySvid}
	s := &SPIREJWTSource{src: fake}

	_, err := s.Token(context.Background(), "vault-aud")
	if err == nil {
		t.Fatal("Token: expected error for empty marshalled token, got nil")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Errorf("error should name empty-token branch, got: %v", err)
	}
}
