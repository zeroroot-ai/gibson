package zitadel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// The platform-operator calls EnsureProject on each drift re-check, every
// five minutes, and EnsureHumanUserNoPassword on the first pass after a
// restore. A create of an object that exists makes Zitadel insert its unique
// name again, and Postgres logs a duplicate key ERROR each time (drill run
// 38559335748, staging). These tests hold the order: look up first, create
// only on NotFound, and resolve a create conflict by a second lookup.

// lookupFirstServer is a fake Zitadel with one lookup path and one create
// path. found decides what the lookup answers on each call.
type lookupFirstServer struct {
	mu          sync.Mutex
	lookupPath  string
	createPath  string
	lookups     int
	creates     int
	found       func(call int) (status int, body string)
	createReply func() (status int, body string)
}

func (f *lookupFirstServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case f.lookupPath:
			f.lookups++
			status, body := f.found(f.lookups)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case f.createPath:
			f.creates++
			status, body := f.createReply()
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *lookupFirstServer) counts() (lookups, creates int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups, f.creates
}

const (
	projectSearchPath = "/management/v1/projects/_search"
	projectCreatePath = "/management/v1/projects"
	userListPath      = "/zitadel.user.v2.UserService/ListUsers"
	userAddPath       = "/zitadel.user.v2.UserService/AddHumanUser"

	projectFound   = `{"result":[{"id":"PROJ-1","name":"gibson"}]}`
	userFound      = `{"result":[{"userId":"UID-1"}]}`
	noResult       = `{"result":[]}`
	alreadyExists  = `{"code":"already_exists","message":"exists"}`
	internalErrMsg = `{"message":"internal"}`
)

func always(status int, body string) func(int) (int, string) {
	return func(int) (int, string) { return status, body }
}

// emptyThenFound answers the first lookup with no result and each later one
// with body: the object appeared between the lookup and the create.
func emptyThenFound(body string) func(int) (int, string) {
	return func(call int) (int, string) {
		if call == 1 {
			return http.StatusOK, noResult
		}
		return http.StatusOK, body
	}
}

func newLookupFirstServer(t *testing.T, lookupPath, createPath string, found func(int) (int, string), createStatus int, createBody string) (*lookupFirstServer, *httpClient) {
	t.Helper()
	f := &lookupFirstServer{
		lookupPath: lookupPath, createPath: createPath, found: found,
		createReply: func() (int, string) { return createStatus, createBody },
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c, ok := New(srv.URL, "pat", testDomain).(*httpClient)
	if !ok {
		t.Fatal("New did not return an *httpClient")
	}
	return f, c
}

func TestEnsureProject_LooksUpFirst(t *testing.T) {
	cases := []struct {
		name        string
		found       func(int) (int, string)
		createCode  int
		createBody  string
		wantID      string
		wantErr     bool
		wantCreates int
	}{
		{"an existing project gets no create", always(http.StatusOK, projectFound), http.StatusOK, `{"id":"NEW"}`, "PROJ-1", false, 0},
		{"a missing project gets one create", always(http.StatusOK, noResult), http.StatusOK, `{"id":"PROJ-NEW"}`, "PROJ-NEW", false, 1},
		{"a create conflict resolves by name", emptyThenFound(projectFound), http.StatusConflict, alreadyExists, "PROJ-1", false, 1},
		{"a failed lookup creates nothing", always(http.StatusInternalServerError, internalErrMsg), http.StatusOK, `{"id":"NEW"}`, "", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newLookupFirstServer(t, projectSearchPath, projectCreatePath, tc.found, tc.createCode, tc.createBody)
			id, err := c.EnsureProject(context.Background(), "gibson")
			if (err != nil) != tc.wantErr {
				t.Fatalf("EnsureProject err = %v, want error %v", err, tc.wantErr)
			}
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if _, creates := f.counts(); creates != tc.wantCreates {
				t.Errorf("creates = %d, want %d", creates, tc.wantCreates)
			}
		})
	}
}

func TestEnsureHumanUserNoPassword_LooksUpFirst(t *testing.T) {
	cases := []struct {
		name        string
		found       func(int) (int, string)
		createCode  int
		createBody  string
		wantID      string
		wantErr     bool
		wantCreates int
	}{
		{"an existing user gets no create", always(http.StatusOK, userFound), http.StatusOK, `{"userId":"NEW"}`, "UID-1", false, 0},
		{"a missing user gets one create", always(http.StatusOK, noResult), http.StatusOK, `{"userId":"UID-NEW"}`, "UID-NEW", false, 1},
		{"a create conflict resolves by email", emptyThenFound(userFound), http.StatusConflict, alreadyExists, "UID-1", false, 1},
		{"a failed lookup creates nothing", always(http.StatusInternalServerError, internalErrMsg), http.StatusOK, `{"userId":"NEW"}`, "", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c := newLookupFirstServer(t, userListPath, userAddPath, tc.found, tc.createCode, tc.createBody)
			id, err := c.EnsureHumanUserNoPassword(context.Background(), "ORG-1", "owner@example.com", "Platform", "Owner")
			if (err != nil) != tc.wantErr {
				t.Fatalf("EnsureHumanUserNoPassword err = %v, want error %v", err, tc.wantErr)
			}
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if _, creates := f.counts(); creates != tc.wantCreates {
				t.Errorf("creates = %d, want %d", creates, tc.wantCreates)
			}
		})
	}
}
