// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// The configuration that a manifest gives to a connector, beyond its image or
// endpoint (gibson#1535, gibson#1536, gibson#1538).
//
// A manifest holds no credential value. It names the secrets of the tenant
// that hold the values. The daemon reads each value from the secret store of
// the tenant, and the operator puts it in the pod or in a header. The loader
// refuses a plain variable with a name that looks like a credential, so a
// credential cannot enter the manifest as plain text.

// Values of CredentialHeader and the OAuth client mode.
const (
	// DefaultCredentialHeaderName is the header of a credential when the
	// manifest names none.
	DefaultCredentialHeaderName = "Authorization"
	// DefaultCredentialHeaderFormat sends the stored secret as a Bearer token.
	DefaultCredentialHeaderFormat = "Bearer {secret}"
	// OAuthClientDynamic means the daemon registers a client at the vendor
	// (RFC 7591).
	OAuthClientDynamic = "dynamic"
	// OAuthClientTenant means the tenant registers the client and gives the
	// client id and the name of the client secret.
	OAuthClientTenant = "tenant"

	// secretPlaceholder in a format stands for the whole stored secret.
	secretPlaceholder = "secret"
)

// CredentialHeader is the header that carries the credential of a Remote
// connector with auth secret, and the format of its value.
//
// Format holds placeholders in braces. {secret} stands for the whole stored
// secret. Any other placeholder stands for a property of the stored secret,
// which then must be a JSON object. Tenable, for example, states
// "accessKey={accessKey};secretKey={secretKey}".
type CredentialHeader struct {
	Name   string `yaml:"name"`
	Format string `yaml:"format"`
}

var (
	headerNameRE   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	placeholderRE  = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)
	secretNameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	envNameRE      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	credentialyRE  = regexp.MustCompile(`(?i)(SECRET|TOKEN|PASSW|CREDENTIAL|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)`)
	forbiddenHeads = map[string]bool{
		"host": true, "content-length": true, "content-type": true, "transfer-encoding": true,
		"connection": true, "upgrade": true, "te": true, "trailer": true, "cookie": true,
		"set-cookie": true, "proxy-authorization": true, "mcp-session-id": true,
	}
)

// ValidSecretName reports whether name can name a secret of the tenant in a
// manifest or in an enable request.
//
// A name under "connector/" is refused. The store keeps the grant and the access
// token of a connector under that prefix, and no manifest or tenant may name them.
func ValidSecretName(name string) bool {
	return secretNameRE.MatchString(name) && !strings.Contains(name, "..") &&
		!strings.HasPrefix(name, "connector/")
}

// withDefaults returns the header with the default name and format filled in.
func (h CredentialHeader) withDefaults() CredentialHeader {
	if h.Name == "" {
		h.Name = DefaultCredentialHeaderName
	}
	if h.Format == "" {
		h.Format = DefaultCredentialHeaderFormat
	}
	return h
}

func (s ConnectorSpec) credentialHeader() CredentialHeader {
	return s.CredentialHeader.withDefaults()
}

func (s ConnectorSpec) oauthClient() string {
	if s.Auth != connectorv1alpha1.ConnectorAuthOAuth {
		return ""
	}
	if s.OAuthClient == "" {
		return OAuthClientDynamic
	}
	return s.OAuthClient
}

// Value builds the header value from the stored secret. It refuses a secret
// that lacks a property of the format, and a value with a control character,
// which could end the header and start another.
func (h CredentialHeader) Value(secret []byte) ([]byte, error) {
	h = h.withDefaults()
	var props map[string]json.RawMessage
	var firstErr error
	out := placeholderRE.ReplaceAllStringFunc(h.Format, func(m string) string {
		name := m[1 : len(m)-1]
		if name == secretPlaceholder {
			return string(secret)
		}
		if props == nil {
			if err := json.Unmarshal(secret, &props); err != nil {
				// The JSON error can quote the input, so it is not wrapped.
				firstErr = errors.New("the credential is not a JSON object, but the header format names a property")
				props = map[string]json.RawMessage{}
				return ""
			}
		}
		raw, ok := props[name]
		if !ok {
			if firstErr == nil {
				firstErr = fmt.Errorf("the credential has no property %q that the header format names", name)
			}
			return ""
		}
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return string(raw)
		}
		return str
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if strings.ContainsAny(out, "\r\n\x00") {
		return nil, errors.New("the credential header value holds a control character")
	}
	return []byte(out), nil
}

// validateAuthFields checks the fields that depend on the auth kind.
func validateAuthFields(id string, s ConnectorSpec) error {
	oauth := s.Auth == connectorv1alpha1.ConnectorAuthOAuth
	if !oauth {
		if s.OAuthScope != "" {
			return fmt.Errorf("%s: oauthScope needs auth oauth", id)
		}
		if s.OAuthClient != "" {
			return fmt.Errorf("%s: oauthClient needs auth oauth", id)
		}
	}
	switch s.OAuthClient {
	case "", OAuthClientDynamic, OAuthClientTenant:
	default:
		return fmt.Errorf("%s: oauthClient %q must be %s or %s", id, s.OAuthClient, OAuthClientDynamic, OAuthClientTenant)
	}
	if s.OAuthScope != "" && strings.ContainsAny(s.OAuthScope, "\r\n\t\"\\") {
		return fmt.Errorf("%s: oauthScope holds a character that a scope cannot hold", id)
	}
	h := s.CredentialHeader
	if h == (CredentialHeader{}) {
		return nil
	}
	if s.Shape != connectorv1alpha1.ConnectorShapeRemote || s.Auth != connectorv1alpha1.ConnectorAuthSecret {
		return fmt.Errorf("%s: credentialHeader needs a Remote connector with auth secret", id)
	}
	if h.Name != "" && (!headerNameRE.MatchString(h.Name) || forbiddenHeads[strings.ToLower(h.Name)]) {
		return fmt.Errorf("%s: credentialHeader name %q is not a header that a connector can set", id, h.Name)
	}
	f := h.withDefaults().Format
	if len(f) > 512 || strings.ContainsAny(f, "\r\n\x00") {
		return fmt.Errorf("%s: credentialHeader format is too long or holds a control character", id)
	}
	if len(placeholderRE.FindAllString(f, -1)) == 0 {
		return fmt.Errorf("%s: credentialHeader format %q holds no placeholder such as {secret}", id, f)
	}
	if strings.Count(f, "{") != strings.Count(f, "}") ||
		strings.Count(f, "{") != len(placeholderRE.FindAllString(f, -1)) {
		return fmt.Errorf("%s: credentialHeader format %q has a brace that is not part of a placeholder", id, f)
	}
	return nil
}

// ConnectorCredential is one credential of a Hosted connector: a named secret
// of the tenant that reaches the pod as the environment variable Env. Property
// selects a field of a JSON secret.
type ConnectorCredential struct {
	Secret   string `yaml:"secret"`
	Property string `yaml:"property"`
	Env      string `yaml:"env"`
}

// validateHostedCredentials checks the credentials of a Hosted connector and
// returns the variable names that they set.
func validateHostedCredentials(id string, creds []ConnectorCredential) (map[string]bool, error) {
	seen := map[string]bool{}
	for _, c := range creds {
		if !ValidSecretName(c.Secret) {
			return nil, fmt.Errorf("%s: credentials secret %q is not a valid secret name", id, c.Secret)
		}
		if !envNameRE.MatchString(c.Env) {
			return nil, fmt.Errorf("%s: credentials env %q is not a valid variable name", id, c.Env)
		}
		if seen[c.Env] {
			return nil, fmt.Errorf("%s: variable %q is set twice", id, c.Env)
		}
		seen[c.Env] = true
	}
	return seen, nil
}

// validateHostedEnv checks the plain variables of a Hosted connector. seen
// holds the names that the credentials set.
func validateHostedEnv(id string, env map[string]string, seen map[string]bool) error {
	for name, value := range env {
		if !envNameRE.MatchString(name) {
			return fmt.Errorf("%s: env %q is not a valid variable name", id, name)
		}
		if seen[name] {
			return fmt.Errorf("%s: variable %q is set twice", id, name)
		}
		if credentialyRE.MatchString(name) {
			return fmt.Errorf("%s: env %q looks like a credential: state it in credentials, which names a secret", id, name)
		}
		if len(value) > 1024 || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s: env %q has a value that is too long or holds a control character", id, name)
		}
	}
	return nil
}

// validateHostedConfig checks the five kinds of Hosted configuration. A
// Remote connector states none of them.
func validateHostedConfig(id string, s ConnectorSpec) error {
	hasConfig := len(s.Credentials) > 0 || len(s.Env) > 0 || len(s.Args) > 0 || s.Port != 0 || s.ImagePullSecret != ""
	if s.Shape != connectorv1alpha1.ConnectorShapeHosted {
		if hasConfig {
			return fmt.Errorf("%s: credentials, env, args, port and imagePullSecret need a Hosted connector", id)
		}
		return nil
	}
	seen, err := validateHostedCredentials(id, s.Credentials)
	if err != nil {
		return err
	}
	if err := validateHostedEnv(id, s.Env, seen); err != nil {
		return err
	}
	for _, a := range s.Args {
		if a == "" || len(a) > 256 || strings.ContainsAny(a, "\r\n\x00") {
			return fmt.Errorf("%s: args holds an empty argument, a long argument or a control character", id)
		}
	}
	if s.Port != 0 && (s.Port < 1024 || s.Port > 65535) {
		return fmt.Errorf("%s: port %d must be from 1024 to 65535: the pod runs as a non-root user", id, s.Port)
	}
	if s.ImagePullSecret != "" && !ValidSecretName(s.ImagePullSecret) {
		return fmt.Errorf("%s: imagePullSecret %q is not a valid secret name", id, s.ImagePullSecret)
	}
	return nil
}
