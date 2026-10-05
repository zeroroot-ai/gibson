// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func emailServer(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-pat", testDomain)
}

func TestToSMTPProviderBody_NoAuthVsPlainAuth(t *testing.T) {
	noAuth := toSMTPProviderBody(SMTPProviderConfig{
		SenderAddress: "no-reply@example.com", SenderName: "Example", TLS: true, Host: "smtp.example.com:587",
	})
	if _, ok := noAuth["none"]; !ok {
		t.Fatalf("no-auth body = %+v, want a \"none\" key", noAuth)
	}
	if _, ok := noAuth["plain"]; ok {
		t.Fatalf("no-auth body = %+v, want no \"plain\" key", noAuth)
	}
	if _, ok := noAuth["user"]; ok {
		t.Fatalf("no-auth body = %+v, want no \"user\" key", noAuth)
	}

	plain := toSMTPProviderBody(SMTPProviderConfig{
		SenderAddress: "no-reply@example.com", SenderName: "Example", TLS: true,
		Host: "smtp.example.com:587", User: "smtp-user", Password: "smtp-pass",
		ReplyToAddress: "replyto@example.com", Description: "gibson-platform-operator",
	})
	if _, ok := plain["none"]; ok {
		t.Fatalf("plain-auth body = %+v, want no \"none\" key", plain)
	}
	authField, ok := plain["plain"].(map[string]any)
	if !ok {
		t.Fatalf("plain-auth body = %+v, want a \"plain\" object", plain)
	}
	if authField["password"] != "smtp-pass" {
		t.Fatalf("plain.password = %v, want smtp-pass", authField["password"])
	}
	if plain["user"] != "smtp-user" {
		t.Fatalf("user = %v, want smtp-user", plain["user"])
	}
	if plain["replyToAddress"] != "replyto@example.com" || plain["description"] != "gibson-platform-operator" {
		t.Fatalf("body = %+v, missing optional fields", plain)
	}
}

func TestSMTPProviderState_Matches(t *testing.T) {
	cfg := SMTPProviderConfig{
		SenderAddress: "a@b.com", SenderName: "N", TLS: true, Host: "h:587", User: "u", ReplyToAddress: "r@b.com",
	}
	same := SMTPProviderState{IsSMTP: true, SenderAddress: "a@b.com", SenderName: "N", TLS: true, Host: "h:587", User: "u", ReplyToAddress: "r@b.com"}
	if !same.Matches(cfg) {
		t.Fatal("Matches = false, want true for identical settings")
	}
	notSMTP := same
	notSMTP.IsSMTP = false
	if notSMTP.Matches(cfg) {
		t.Fatal("Matches = true for an HTTP provider, want false")
	}
	driftedHost := same
	driftedHost.Host = "other:587"
	if driftedHost.Matches(cfg) {
		t.Fatal("Matches = true despite a drifted host, want false")
	}
}

func TestAddSMTPEmailProvider(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/email/smtp" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["host"] != "smtp.example.com:587" {
			t.Errorf("body = %+v", body)
		}
		_, _ = w.Write([]byte(`{"details":{"sequence":"1"},"id":"PROVIDER-1"}`))
	})
	id, err := c.AddSMTPEmailProvider(context.Background(), SMTPProviderConfig{
		SenderAddress: "a@b.com", SenderName: "N", Host: "smtp.example.com:587",
	})
	if err != nil || id != "PROVIDER-1" {
		t.Fatalf("AddSMTPEmailProvider = %q, %v", id, err)
	}
}

func TestAddSMTPEmailProvider_Errors(t *testing.T) {
	forbidden := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if _, err := forbidden.AddSMTPEmailProvider(context.Background(), SMTPProviderConfig{}); !IsPermanent(err) {
		t.Errorf("403 = %v, want IsPermanent", err)
	}

	emptyID := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	if _, err := emptyID.AddSMTPEmailProvider(context.Background(), SMTPProviderConfig{}); !errors.Is(err, ErrUnreachable) {
		t.Errorf("empty id = %v, want ErrUnreachable", err)
	}

	unreachable := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := unreachable.AddSMTPEmailProvider(context.Background(), SMTPProviderConfig{}); err == nil || IsPermanent(err) {
		t.Errorf("500 = %v, want a non-permanent error", err)
	}
}

func TestUpdateSMTPEmailProvider(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/admin/v1/email/smtp/PROVIDER-1" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"details":{}}`))
	})
	if err := c.UpdateSMTPEmailProvider(context.Background(), "PROVIDER-1", SMTPProviderConfig{Host: "h:587"}); err != nil {
		t.Fatalf("UpdateSMTPEmailProvider: %v", err)
	}
}

func TestUpdateSMTPEmailProvider_Error(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := c.UpdateSMTPEmailProvider(context.Background(), "PROVIDER-1", SMTPProviderConfig{}); err == nil {
		t.Fatal("UpdateSMTPEmailProvider: expected an error")
	}
}

func TestActivateEmailProvider(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/email/PROVIDER-1/_activate" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"details":{}}`))
	})
	if err := c.ActivateEmailProvider(context.Background(), "PROVIDER-1"); err != nil {
		t.Fatalf("ActivateEmailProvider: %v", err)
	}
}

func TestActivateEmailProvider_Error(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	if err := c.ActivateEmailProvider(context.Background(), "PROVIDER-1"); !IsPermanent(err) {
		t.Errorf("403 = %v, want IsPermanent", err)
	}
}

func TestFindSMTPEmailProviderByDescription(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/email/_search" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		// Shaped exactly as protojson would emit ListEmailProvidersResponse:
		// a numeric proto field (details.sequence, a uint64) rendered as a
		// JSON string, alongside an entry whose description does not match
		// and one that does.
		_, _ = w.Write([]byte(`{
			"details": {"totalResult": "2", "processedSequence": "9"},
			"result": [
				{"details":{"sequence":"1"},"id":"OTHER","state":"EMAIL_PROVIDER_INACTIVE","description":"someone-else"},
				{"details":{"sequence":"2"},"id":"PROVIDER-1","state":"EMAIL_PROVIDER_ACTIVE","description":"gibson-platform-operator","smtp":{"host":"h:587"}}
			]
		}`))
	})
	id, err := c.FindSMTPEmailProviderByDescription(context.Background(), "gibson-platform-operator")
	if err != nil || id != "PROVIDER-1" {
		t.Fatalf("FindSMTPEmailProviderByDescription = %q, %v", id, err)
	}
}

func TestFindSMTPEmailProviderByDescription_NotFound(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[]}`))
	})
	if _, err := c.FindSMTPEmailProviderByDescription(context.Background(), "gibson-platform-operator"); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty result = %v, want ErrNotFound", err)
	}
}

func TestFindSMTPEmailProviderByDescription_TransientError(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := c.FindSMTPEmailProviderByDescription(context.Background(), "x"); err == nil || IsPermanent(err) {
		t.Errorf("500 = %v, want a non-permanent error", err)
	}
}

func TestGetSMTPEmailProviderState(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/v1/email/PROVIDER-1" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		// Shaped exactly as protojson emits GetEmailProviderByIdResponse:
		// note details.sequence (a proto uint64) rendered as a JSON string,
		// which this decode must tolerate without ever mapping it onto a
		// non-string Go field.
		_, _ = w.Write([]byte(`{
			"config": {
				"details": {"sequence": "42"},
				"id": "PROVIDER-1",
				"state": "EMAIL_PROVIDER_ACTIVE",
				"description": "gibson-platform-operator",
				"smtp": {
					"senderAddress": "no-reply@example.com",
					"senderName": "Example",
					"tls": true,
					"host": "smtp.example.com:587",
					"user": "smtp-user",
					"replyToAddress": "replyto@example.com"
				}
			}
		}`))
	})
	state, err := c.GetSMTPEmailProviderState(context.Background(), "PROVIDER-1")
	if err != nil {
		t.Fatalf("GetSMTPEmailProviderState: %v", err)
	}
	want := SMTPProviderState{
		ID: "PROVIDER-1", Active: true, IsSMTP: true,
		SenderAddress: "no-reply@example.com", SenderName: "Example", TLS: true,
		Host: "smtp.example.com:587", User: "smtp-user", ReplyToAddress: "replyto@example.com",
	}
	if state != want {
		t.Fatalf("GetSMTPEmailProviderState = %+v, want %+v", state, want)
	}
}

func TestGetSMTPEmailProviderState_HTTPProvider(t *testing.T) {
	// A provider occupying the id that is an HTTP provider, not SMTP: the
	// smtp key is absent entirely (protojson omits an unset oneof arm).
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"config":{"id":"PROVIDER-1","state":"EMAIL_PROVIDER_ACTIVE","http":{"endpoint":"https://relay.example.com"}}}`))
	})
	state, err := c.GetSMTPEmailProviderState(context.Background(), "PROVIDER-1")
	if err != nil {
		t.Fatalf("GetSMTPEmailProviderState: %v", err)
	}
	if state.IsSMTP {
		t.Fatalf("IsSMTP = true for an HTTP provider, want false")
	}
}

func TestGetSMTPEmailProviderState_NotFound(t *testing.T) {
	c := emailServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if _, err := c.GetSMTPEmailProviderState(context.Background(), "GONE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 = %v, want ErrNotFound", err)
	}
}

func TestIsSMTPProviderActive(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		want bool
		err  bool
	}{
		{
			name: "active smtp",
			h: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"config":{"id":"P1","state":"EMAIL_PROVIDER_ACTIVE","smtp":{"host":"h:587"}}}`))
			},
			want: true,
		},
		{
			name: "http provider is not smtp",
			h: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"config":{"id":"P1","state":"EMAIL_PROVIDER_ACTIVE","http":{"endpoint":"https://x"}}}`))
			},
			want: false,
		},
		{
			name: "no provider configured at all",
			h: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			want: false,
		},
		{
			name: "transient error",
			h: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			want: false,
			err:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := emailServer(t, tc.h)
			got, err := c.IsSMTPProviderActive(context.Background())
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want err=%v", err, tc.err)
			}
			if got != tc.want {
				t.Fatalf("IsSMTPProviderActive = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEmailProviderErrClient(t *testing.T) {
	sentinel := errors.New("boom")
	c := &errClient{err: sentinel}
	if _, err := c.AddSMTPEmailProvider(context.Background(), SMTPProviderConfig{}); !errors.Is(err, sentinel) {
		t.Errorf("AddSMTPEmailProvider = %v", err)
	}
	if err := c.UpdateSMTPEmailProvider(context.Background(), "x", SMTPProviderConfig{}); !errors.Is(err, sentinel) {
		t.Errorf("UpdateSMTPEmailProvider = %v", err)
	}
	if err := c.ActivateEmailProvider(context.Background(), "x"); !errors.Is(err, sentinel) {
		t.Errorf("ActivateEmailProvider = %v", err)
	}
	if _, err := c.FindSMTPEmailProviderByDescription(context.Background(), "x"); !errors.Is(err, sentinel) {
		t.Errorf("FindSMTPEmailProviderByDescription = %v", err)
	}
	if _, err := c.GetSMTPEmailProviderState(context.Background(), "x"); !errors.Is(err, sentinel) {
		t.Errorf("GetSMTPEmailProviderState = %v", err)
	}
	if _, err := c.IsSMTPProviderActive(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("IsSMTPProviderActive = %v", err)
	}
}
