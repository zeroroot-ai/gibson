package zitadel_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/idp/zitadel"
)

// setupV2Server stands up an httptest server that serves OIDC discovery + the
// OAuth2 token endpoint (via writeOIDCBootstrap) so zitadel.New succeeds, and
// routes the Zitadel v2 user API calls (/v2/users...) to the provided handler.
func setupV2Server(t *testing.T, v2Handler http.HandlerFunc) zitadel.Config {
	t.Helper()
	var srvURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if writeOIDCBootstrap(w, r, func() string { return srvURL }) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v2/users") {
			v2Handler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(handler)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return zitadel.Config{Issuer: srv.URL, ClientID: "admin-client", ClientSecret: "admin-secret", OrgID: "org-123"}
}

// writeOIDCBootstrap answers the OIDC discovery and OAuth2 token requests that
// zitadel.New's startup probe makes. It returns true when it handled the
// request so the caller can stop routing. baseURL is a thunk because the
// httptest server URL is only known after the server starts.
func writeOIDCBootstrap(w http.ResponseWriter, r *http.Request, baseURL func() string) bool {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": baseURL() + "/oauth/v2/token"})
		return true
	case "/oauth/v2/token":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-admin-token", "token_type": "Bearer", "expires_in": 3600,
		})
		return true
	default:
		return false
	}
}

// closeClient closes the client, satisfying errcheck without a per-call
// boilerplate closure.
func closeClient(t *testing.T, c interface{ Close() error }) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("client.Close: %v", err)
	}
}

func TestCreateHumanUser_HappyPath(t *testing.T) {
	var gotBody map[string]interface{}
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/users/human" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		jsonResp(w, http.StatusCreated, map[string]string{"userId": "user-new"})
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	res, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		Email:         "owner@example.com",
		GivenName:     "Ada",
		FamilyName:    "Lovelace",
		Password:      "s3cret-passw0rd!",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("CreateHumanUser: %v", err)
	}
	if res.UserID != "user-new" {
		t.Errorf("UserID = %q, want user-new", res.UserID)
	}
	if res.AlreadyExisted {
		t.Errorf("AlreadyExisted = true, want false on create")
	}

	// Verify request shape mirrors the dashboard's createHumanUser body.
	if gotBody["username"] != "owner@example.com" {
		t.Errorf("username = %v", gotBody["username"])
	}
	prof, _ := gotBody["profile"].(map[string]interface{})
	if prof["givenName"] != "Ada" || prof["familyName"] != "Lovelace" {
		t.Errorf("profile = %v", prof)
	}
	email, _ := gotBody["email"].(map[string]interface{})
	if email["isVerified"] != true {
		t.Errorf("email.isVerified = %v, want true", email["isVerified"])
	}
	pw, _ := gotBody["password"].(map[string]interface{})
	if pw["password"] != "s3cret-passw0rd!" {
		t.Errorf("password not forwarded in body")
	}
	if pw["changeRequired"] != false {
		t.Errorf("changeRequired = %v, want false", pw["changeRequired"])
	}
}

func TestCreateHumanUser_ResumeOn409(t *testing.T) {
	var sawSearch, sawPasswordReset bool
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users/human":
			// Conflict — user already exists.
			errorResp(w, http.StatusConflict, "ALREADY_EXISTS", "user already exists")
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users":
			sawSearch = true
			jsonResp(w, http.StatusOK, map[string]interface{}{
				"result": []map[string]string{{"userId": "user-existing"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v2/users/user-existing/password":
			sawPasswordReset = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	res, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{
		Email:    "owner@example.com",
		Password: "new-passw0rd!",
	})
	if err != nil {
		t.Fatalf("CreateHumanUser resume: %v", err)
	}
	if res.UserID != "user-existing" {
		t.Errorf("UserID = %q, want user-existing", res.UserID)
	}
	if !res.AlreadyExisted {
		t.Errorf("AlreadyExisted = false, want true on resume")
	}
	if !sawSearch {
		t.Errorf("expected a by-email search on 409")
	}
	if !sawPasswordReset {
		t.Errorf("expected a password reset on the resumed user")
	}
}

func TestCreateHumanUser_RequiresEmailAndPassword(t *testing.T) {
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if _, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{Password: "x"}); err == nil {
		t.Errorf("expected error when email is empty")
	}
	if _, err := client.CreateHumanUser(context.Background(), idp.CreateHumanUserRequest{Email: "a@b.c"}); err == nil {
		t.Errorf("expected error when password is empty")
	}
}

func TestSetUserPassword_PostsToPasswordEndpoint(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/password") {
			http.NotFound(w, r)
			return
		}
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if err := client.SetUserPassword(context.Background(), "user-7", "p@ssw0rd"); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if gotPath != "/v2/users/user-7/password" {
		t.Errorf("path = %q", gotPath)
	}
	np, _ := gotBody["newPassword"].(map[string]interface{})
	if np["password"] != "p@ssw0rd" {
		t.Errorf("newPassword.password not forwarded: %v", gotBody)
	}
}

func TestSetUserPassword_RequiresArgs(t *testing.T) {
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	client, _ := zitadel.New(context.Background(), cfg)
	defer closeClient(t, client)

	if err := client.SetUserPassword(context.Background(), "", "p"); err == nil {
		t.Errorf("expected error on empty userID")
	}
	if err := client.SetUserPassword(context.Background(), "u", ""); err == nil {
		t.Errorf("expected error on empty password")
	}
}

func TestSendVerificationEmail_PostsResend(t *testing.T) {
	var gotPath string
	cfg := setupV2Server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/email/resend") {
			http.NotFound(w, r)
			return
		}
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	client, err := zitadel.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closeClient(t, client)

	if err := client.SendVerificationEmail(context.Background(), "user-9"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}
	if gotPath != "/v2/users/user-9/email/resend" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestSendVerificationEmail_ErrorIsReturned(t *testing.T) {
	// A user created already-verified has no pending code; Zitadel returns 400.
	// The method returns the (mapped) error so the caller can log it; the
	// caller — SignupService.Signup — treats it as non-fatal.
	cfg := setupV2Server(t, func(w http.ResponseWriter, _ *http.Request) {
		errorResp(w, http.StatusBadRequest, "EMAIL-5w5ilin4yt", "Code is empty")
	})
	client, _ := zitadel.New(context.Background(), cfg)
	defer closeClient(t, client)

	if err := client.SendVerificationEmail(context.Background(), "user-9"); err == nil {
		t.Errorf("expected an error from a 400 resend")
	}
}
