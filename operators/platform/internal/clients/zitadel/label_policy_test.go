// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package zitadel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func labelServer(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-pat", "app.example.test")
}

func TestLabelAsset_FetchesThePathFromTheBaseURLWithTheInstanceHost(t *testing.T) {
	c := labelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/assets/v1/inst/policy/label/logo-1" || r.URL.RawQuery != "v=2" {
			t.Errorf("request = %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if r.Host != "app.example.test" {
			t.Errorf("Host = %q, want the instance host", r.Host)
		}
		_, _ = w.Write([]byte("<svg/>"))
	})
	got, err := c.LabelAsset(context.Background(), "https://app.example.test/assets/v1/inst/policy/label/logo-1?v=2")
	if err != nil || string(got) != "<svg/>" {
		t.Fatalf("LabelAsset = %q, %v", got, err)
	}
}

func TestLabelAsset_Errors(t *testing.T) {
	c := labelServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	if _, err := c.LabelAsset(context.Background(), "https://x/assets/a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 = %v, want ErrNotFound", err)
	}
	if _, err := c.LabelAsset(context.Background(), "::bad"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad URL = %v, want ErrInvalidInput", err)
	}
}

func TestUploadLabelAsset_SendsTheSVGAsTheFileField(t *testing.T) {
	c := labelServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/assets/v1/instance/policy/label/logo/dark" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-pat" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("FormFile: %v", err)
		}
		b, _ := io.ReadAll(f)
		if string(b) != "<svg>mark</svg>" || h.Header.Get("Content-Type") != "image/svg+xml" {
			t.Errorf("file = %q (%s)", b, h.Header.Get("Content-Type"))
		}
	})
	if err := c.UploadLabelAsset(context.Background(), LabelSlots[1], []byte("<svg>mark</svg>")); err != nil {
		t.Fatal(err)
	}
}

func TestUploadLabelAsset_RefusedUpload(t *testing.T) {
	c := labelServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusRequestEntityTooLarge) })
	if err := c.UploadLabelAsset(context.Background(), LabelSlots[0], []byte("x")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("413 = %v, want ErrInvalidInput", err)
	}
}

func TestRemoveLabelAsset_AnEmptySlotIsSuccess(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusPreconditionFailed} {
		c := labelServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/admin/v1/policies/label/icon_dark" {
				t.Errorf("request = %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(status)
		})
		if err := c.RemoveLabelAsset(context.Background(), LabelSlots[3]); err != nil {
			t.Errorf("status %d: %v, want success", status, err)
		}
	}
	c := labelServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if err := c.RemoveLabelAsset(context.Background(), LabelSlots[3]); !errors.Is(err, ErrUnreachable) {
		t.Errorf("502 = %v, want ErrUnreachable", err)
	}
}

func TestActivateLabelPolicy(t *testing.T) {
	for status, ok := range map[int]bool{http.StatusOK: true, http.StatusConflict: true, http.StatusInternalServerError: false} {
		c := labelServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/admin/v1/policies/label/_activate" {
				t.Errorf("path = %s", r.URL.Path)
			}
			w.WriteHeader(status)
		})
		if err := c.ActivateLabelPolicy(context.Background()); (err == nil) != ok {
			t.Errorf("status %d: err = %v, want ok=%v", status, err, ok)
		}
	}
}

func TestGetAndUpdateLabelPolicy(t *testing.T) {
	c := labelServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"policy":{"primaryColor":"#346000"}}`))
		case http.MethodPut:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"Label Policy has not been changed"}`))
		}
	})
	p, err := c.GetLabelPolicy(context.Background())
	if err != nil || p["primaryColor"] != "#346000" {
		t.Fatalf("GetLabelPolicy = %v, %v", p, err)
	}
	if err := c.UpdateLabelPolicy(context.Background(), p); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("UpdateLabelPolicy 400 = %v, want ErrInvalidInput", err)
	}
	empty := labelServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	if _, err := empty.GetLabelPolicy(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("no policy = %v, want ErrUnreachable", err)
	}
}

func TestStatusError(t *testing.T) {
	cases := map[int]error{
		http.StatusNotFound:            ErrNotFound,
		http.StatusUnauthorized:        ErrPermanent,
		http.StatusForbidden:           ErrUnauthorized,
		http.StatusTooManyRequests:     ErrRateLimited,
		http.StatusBadRequest:          ErrInvalidInput,
		http.StatusInternalServerError: ErrUnreachable,
	}
	for status, want := range cases {
		if err := statusError(http.MethodGet, "/p", status, nil); !errors.Is(err, want) {
			t.Errorf("statusError(%d) = %v, want %v", status, err, want)
		}
	}
}

func TestDoRaw_TransportFailureIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	c := New(srv.URL, "p", "")
	if _, err := c.LabelAsset(context.Background(), srv.URL+"/assets/a"); !errors.Is(err, ErrUnreachable) {
		t.Errorf("closed server = %v, want ErrUnreachable", err)
	}
}

func TestErrClient_LabelPolicy(t *testing.T) {
	c := New("://bad", "p", "")
	ctx := context.Background()
	if _, err := c.GetLabelPolicy(ctx); err == nil {
		t.Error("GetLabelPolicy")
	}
	if err := c.UpdateLabelPolicy(ctx, nil); err == nil {
		t.Error("UpdateLabelPolicy")
	}
	if _, err := c.LabelAsset(ctx, "x"); err == nil {
		t.Error("LabelAsset")
	}
	if err := c.RemoveLabelAsset(ctx, LabelSlots[0]); err == nil {
		t.Error("RemoveLabelAsset")
	}
	if err := c.UploadLabelAsset(ctx, LabelSlots[0], nil); err == nil {
		t.Error("UploadLabelAsset")
	}
	if err := c.ActivateLabelPolicy(ctx); err == nil {
		t.Error("ActivateLabelPolicy")
	}
}
