// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// DockerConfigFileName is the file a registry credential directory holds. It is
// a docker config, so the name is the one every registry tool already reads.
const DockerConfigFileName = "config.json"

// DockerConfigPath returns the file a credential directory holds. An empty
// directory returns an empty path, which means "no credential is configured".
func DockerConfigPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, DockerConfigFileName)
}

// DockerConfigPresent reports whether a readable credential file sits at path.
// The daemon uses it to tell "no credential was mounted" apart from "a
// credential was mounted and the registry still refused".
func DockerConfigPresent(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// dockerConfigKeychain resolves a registry credential from one docker config
// file. A pod-level imagePullSecret authenticates the kubelet's pull and
// nothing else, so the daemon process needs its own copy of the credential to
// read an image's signature referrers off a private registry.
type dockerConfigKeychain struct{ path string }

// dockerConfig is the part of a docker config this reads. Everything else in
// the file (credential helpers, experimental flags) is not a credential.
type dockerConfig struct {
	Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

// Resolve implements authn.Keychain.
//
// A missing file is not an error: an install whose images pull anonymously
// mounts no credential, and the verification that follows is the thing that
// reports the refusal. A file that exists and cannot be parsed IS an error,
// because it is a misconfiguration an operator must see rather than a
// silent fall back to anonymous.
func (k dockerConfigKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	raw, err := os.ReadFile(k.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return authn.Anonymous, nil
	case err != nil:
		return nil, fmt.Errorf("read the registry credential at %s: %w", k.path, err)
	}
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse the registry credential at %s: %w", k.path, err)
	}
	entry, ok := lookupAuth(cfg.Auths, target)
	if !ok {
		return authn.Anonymous, nil
	}
	return authenticatorFor(entry, k.path)
}

// lookupAuth finds the entry for a target. A docker config keys its entries by
// registry host, and sometimes by the full repository path, so both are tried
// from the most specific to the least.
func lookupAuth(auths map[string]dockerAuth, target authn.Resource) (dockerAuth, bool) {
	if len(auths) == 0 {
		return dockerAuth{}, false
	}
	for _, key := range []string{target.String(), target.RegistryStr()} {
		if entry, ok := auths[key]; ok {
			return entry, true
		}
	}
	return dockerAuth{}, false
}

// authenticatorFor turns one docker config entry into an authenticator. The
// `auth` field is base64 of "username:password" and is what a `docker login`
// writes, so it is read when the pair is not spelled out.
func authenticatorFor(entry dockerAuth, path string) (authn.Authenticator, error) {
	username, password := entry.Username, entry.Password
	if password == "" && entry.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			return nil, fmt.Errorf("decode the registry credential at %s: %w", path, err)
		}
		user, pass, found := strings.Cut(string(decoded), ":")
		if !found {
			return nil, fmt.Errorf("the registry credential at %s has no user and password in its auth field", path)
		}
		username, password = user, pass
	}
	if password == "" {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{Username: username, Password: password}), nil
}

// RegistryCredentialFor reports the credential the verifier would present to a
// registry host. It is how an operator and a test can see that the credential
// reached the verifier, rather than reading a 401 and guessing (gibson#1744).
// An anonymous resolution returns a zero AuthConfig and no error.
func (v *SigstoreVerifier) RegistryCredentialFor(registryHost string) (authn.AuthConfig, error) {
	res, err := name.NewRegistry(registryHost)
	if err != nil {
		return authn.AuthConfig{}, fmt.Errorf("parse the registry %q: %w", registryHost, err)
	}
	auth, err := v.keychain.Resolve(res)
	if err != nil {
		return authn.AuthConfig{}, fmt.Errorf("resolve the credential for %q: %w", registryHost, err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		return authn.AuthConfig{}, fmt.Errorf("read the credential for %q: %w", registryHost, err)
	}
	if cfg == nil {
		return authn.AuthConfig{}, nil
	}
	return *cfg, nil
}
