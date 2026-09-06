// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// These cover the credential the verifier reads a PRIVATE registry with. The
// failure they pin is measured: on a private registry an anonymous verifier
// gets 401 on the referrers request, refuses every first-party image, and the
// platform offers no component while the pod still looks healthy (gibson#1744).

// authRegistry starts an in-process OCI registry that answers 401 unless the
// request carries the given basic credential, and returns its host.
func authRegistry(t *testing.T, username, password string) string {
	t.Helper()
	inner := registry.New()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="gibson-test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse registry URL: %v", err)
	}
	return u.Host
}

// writeDockerConfig writes a docker config for one host into a new directory
// and returns the directory, the shape the chart projects.
func writeDockerConfig(t *testing.T, host, username, password string) string {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`,
		host, base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	if err := os.WriteFile(filepath.Join(dir, DockerConfigFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	return dir
}

// TestFetchBundles_APrivateRegistryRefusesAnAnonymousVerifier is the measured
// failure: without a credential the referrers request never gets past 401.
func TestFetchBundles_APrivateRegistryRefusesAnAnonymousVerifier(t *testing.T) {
	host := authRegistry(t, "x-access-token", "the-pull-token")
	ref, err := name.NewDigest(host + "/gibson@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}

	v := NewSigstoreVerifier("")
	if _, err := v.fetchBundles(context.Background(), ref); err == nil {
		t.Fatal("an anonymous verifier must not reach a private registry")
	}
}

// TestFetchBundles_TheMountedCredentialReachesTheRegistry is the fix: the same
// registry answers once the verifier carries the projected docker config.
func TestFetchBundles_TheMountedCredentialReachesTheRegistry(t *testing.T) {
	const user, pass = "x-access-token", "the-pull-token"
	host := authRegistry(t, user, pass)
	dir := writeDockerConfig(t, host, user, pass)

	subject := pushSubjectAuthenticated(t, host, user, pass)
	attachReferrerAuthenticated(t, subject, bundleMediaType, []byte(`{"mediaType":"x"}`), user, pass)

	v := NewSigstoreVerifier(dir)
	if _, err := v.fetchBundles(context.Background(), subject); err != nil {
		t.Fatalf("the mounted credential must reach the registry: %v", err)
	}
}

// TestDockerConfigKeychain_ReadsTheAuthField covers the form `docker login`
// writes: one base64 of user and password.
func TestDockerConfigKeychain_ReadsTheAuthField(t *testing.T) {
	dir := writeDockerConfig(t, "ghcr.io", "x-access-token", "sekret")
	k := dockerConfigKeychain{path: DockerConfigPath(dir)}

	res, err := name.NewRegistry("ghcr.io")
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	auth, err := k.Resolve(res)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if cfg.Username != "x-access-token" || cfg.Password != "sekret" {
		t.Errorf("resolved %+v, want the user and password from the auth field", cfg)
	}
}

// TestDockerConfigKeychain_ReadsTheSpelledOutPair covers the other form: a
// username and a password as their own fields.
func TestDockerConfigKeychain_ReadsTheSpelledOutPair(t *testing.T) {
	dir := t.TempDir()
	body := `{"auths":{"ghcr.io":{"username":"u","password":"p"}}}`
	if err := os.WriteFile(filepath.Join(dir, DockerConfigFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	auth, err := dockerConfigKeychain{path: DockerConfigPath(dir)}.Resolve(mustRegistry(t, "ghcr.io"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("authorization: %v", err)
	}
	if cfg.Username != "u" || cfg.Password != "p" {
		t.Errorf("resolved %+v, want u and p", cfg)
	}
}

// TestDockerConfigKeychain_NoFileIsAnonymous: an install that pulls anonymously
// mounts nothing, and that is not an error here.
func TestDockerConfigKeychain_NoFileIsAnonymous(t *testing.T) {
	k := dockerConfigKeychain{path: filepath.Join(t.TempDir(), DockerConfigFileName)}
	auth, err := k.Resolve(mustRegistry(t, "ghcr.io"))
	if err != nil {
		t.Fatalf("a missing credential is not an error: %v", err)
	}
	if auth != authn.Anonymous {
		t.Errorf("resolved %v, want anonymous", auth)
	}
}

// TestDockerConfigKeychain_AnotherRegistryIsAnonymous: the credential answers
// for its own host only.
func TestDockerConfigKeychain_AnotherRegistryIsAnonymous(t *testing.T) {
	dir := writeDockerConfig(t, "ghcr.io", "u", "p")
	auth, err := dockerConfigKeychain{path: DockerConfigPath(dir)}.Resolve(mustRegistry(t, "docker.io"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if auth != authn.Anonymous {
		t.Errorf("resolved %v, want anonymous for another registry", auth)
	}
}

// TestDockerConfigKeychain_UnreadableFileIsAnError: a credential that exists
// and cannot be read is a misconfiguration an operator must see, never a
// silent fall back to anonymous.
func TestDockerConfigKeychain_UnreadableFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DockerConfigFileName)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := (dockerConfigKeychain{path: path}).Resolve(mustRegistry(t, "ghcr.io")); err == nil {
		t.Fatal("an unparseable credential must be an error")
	}
}

// TestCredentialPathAndPresence pins the two helpers the daemon reads.
func TestCredentialPathAndPresence(t *testing.T) {
	if DockerConfigPath("") != "" {
		t.Error("no directory means no credential path")
	}
	if DockerConfigPresent("") {
		t.Error("an empty path is never present")
	}
	dir := writeDockerConfig(t, "ghcr.io", "u", "p")
	path := DockerConfigPath(dir)
	if path != filepath.Join(dir, DockerConfigFileName) {
		t.Errorf("path = %q", path)
	}
	if !DockerConfigPresent(path) {
		t.Error("a written credential must read as present")
	}
	if DockerConfigPresent(dir) {
		t.Error("a directory is not a credential")
	}
}

func mustRegistry(t *testing.T, host string) name.Registry {
	t.Helper()
	r, err := name.NewRegistry(host)
	if err != nil {
		t.Fatalf("parse registry %q: %v", host, err)
	}
	return r
}

// pushSubjectAuthenticated pushes an ordinary image to a registry that demands
// a credential, and returns its digest reference.
func pushSubjectAuthenticated(t *testing.T, host, username, password string) name.Digest {
	t.Helper()
	opt := remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: username, Password: password}))
	ref, err := name.NewTag(host + "/gibson:v1")
	if err != nil {
		t.Fatalf("parse tag: %v", err)
	}
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer([]byte("payload"), types.OCILayer),
	})
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	if err := remote.Write(ref, img, opt); err != nil {
		t.Fatalf("push subject: %v", err)
	}
	dg, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return ref.Context().Digest(dg.String())
}

// attachReferrerAuthenticated attaches an artifact to subject on a registry
// that demands a credential.
func attachReferrerAuthenticated(t *testing.T, subject name.Digest, artifactType string, body []byte, username, password string) {
	t.Helper()
	opt := remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: username, Password: password}))
	subjDesc, err := remote.Head(subject, opt)
	if err != nil {
		t.Fatalf("head subject: %v", err)
	}
	art, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(body, types.MediaType(artifactType)),
	})
	if err != nil {
		t.Fatalf("build artifact: %v", err)
	}
	art = mutate.MediaType(art, types.OCIManifestSchema1)
	art = mutate.ConfigMediaType(art, types.MediaType(artifactType))
	art = mutate.Subject(art, *subjDesc).(v1.Image)
	dg, err := art.Digest()
	if err != nil {
		t.Fatalf("artifact digest: %v", err)
	}
	if err := remote.Write(subject.Context().Digest(dg.String()), art, opt); err != nil {
		t.Fatalf("push referrer: %v", err)
	}
}

// TestDockerConfigKeychain_AnUnreadablePathIsAnError: a path that is not a
// file at all is a mount that went wrong, and it must not read as anonymous.
func TestDockerConfigKeychain_AnUnreadablePathIsAnError(t *testing.T) {
	if _, err := (dockerConfigKeychain{path: t.TempDir()}).Resolve(mustRegistry(t, "ghcr.io")); err == nil {
		t.Fatal("a path that is not a file must be an error")
	}
}

// TestDockerConfigKeychain_AnEmptyAuthsMapIsAnonymous covers a projected
// credential that holds no entry at all.
func TestDockerConfigKeychain_AnEmptyAuthsMapIsAnonymous(t *testing.T) {
	auth, err := resolveConfig(t, `{"auths":{}}`, "ghcr.io")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if auth != authn.Anonymous {
		t.Errorf("resolved %v, want anonymous", auth)
	}
}

// TestDockerConfigKeychain_AnUndecodableAuthFieldIsAnError covers a docker
// config whose auth field is not base64.
func TestDockerConfigKeychain_AnUndecodableAuthFieldIsAnError(t *testing.T) {
	if _, err := resolveConfig(t, `{"auths":{"ghcr.io":{"auth":"!!not base64!!"}}}`, "ghcr.io"); err == nil {
		t.Fatal("an undecodable auth field must be an error")
	}
}

// TestDockerConfigKeychain_AnAuthFieldWithNoColonIsAnError covers a decoded
// auth field that does not hold a user and a password.
func TestDockerConfigKeychain_AnAuthFieldWithNoColonIsAnError(t *testing.T) {
	body := fmt.Sprintf(`{"auths":{"ghcr.io":{"auth":%q}}}`,
		base64.StdEncoding.EncodeToString([]byte("no-colon-here")))
	if _, err := resolveConfig(t, body, "ghcr.io"); err == nil {
		t.Fatal("an auth field with no colon must be an error")
	}
}

// TestDockerConfigKeychain_AnEntryWithNoPasswordIsAnonymous: an entry that
// carries no password authenticates nothing, and saying so beats sending a
// half credential.
func TestDockerConfigKeychain_AnEntryWithNoPasswordIsAnonymous(t *testing.T) {
	auth, err := resolveConfig(t, `{"auths":{"ghcr.io":{"username":"u"}}}`, "ghcr.io")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if auth != authn.Anonymous {
		t.Errorf("resolved %v, want anonymous", auth)
	}
}

// TestRegistryCredentialFor_ReportsTheMountedCredential is the diagnostic an
// operator reads instead of guessing at a 401.
func TestRegistryCredentialFor_ReportsTheMountedCredential(t *testing.T) {
	dir := writeDockerConfig(t, "ghcr.io", "x-access-token", "sekret")
	cfg, err := NewSigstoreVerifier(dir).RegistryCredentialFor("ghcr.io")
	if err != nil {
		t.Fatalf("report the credential: %v", err)
	}
	if cfg.Username != "x-access-token" || cfg.Password != "sekret" {
		t.Errorf("reported %+v, want the mounted credential", cfg)
	}
}

// TestRegistryCredentialFor_AnUnparseableHostIsAnError pins the argument check.
func TestRegistryCredentialFor_AnUnparseableHostIsAnError(t *testing.T) {
	if _, err := NewSigstoreVerifier("").RegistryCredentialFor("not a registry"); err == nil {
		t.Fatal("an unparseable host must be an error")
	}
}

// TestRegistryCredentialFor_ABrokenCredentialIsAnError: a mount that went
// wrong is reported here rather than swallowed into an anonymous request.
func TestRegistryCredentialFor_ABrokenCredentialIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DockerConfigFileName), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewSigstoreVerifier(dir).RegistryCredentialFor("ghcr.io"); err == nil {
		t.Fatal("a broken credential must be an error")
	}
}

// resolveConfig writes body as the projected docker config and resolves host
// through the keychain.
func resolveConfig(t *testing.T, body, host string) (authn.Authenticator, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, DockerConfigFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	return dockerConfigKeychain{path: DockerConfigPath(dir)}.Resolve(mustRegistry(t, host))
}
