// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package zitadel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
)

// pinnedZitadelImage is the Zitadel release that the chart pins
// (charts: helm/gibson/values.yaml, zitadel.image.tag). Move it with the pin.
const pinnedZitadelImage = "ghcr.io/zitadel/zitadel:v4.19.4"

// publicHost is the claimed public host of the test instance. It has no port,
// as in production (zitadelconn refuses a ported host).
const publicHost = "auth.example.test"

// serviceHost is the in-cluster name that a component dials. No trusted domain
// is registered for it.
const serviceHost = "gibson-zitadel:8080"

// TestInstanceHeaderAloneSelectsTheInstance is the proof that ADR-0092 asks
// for (gibson#990). On the pinned Zitadel release, with no trusted domain for
// the Service name, a request to the Service name selects the instance when it
// carries the x-zitadel-instance-host header, and gets 404 without it.
func TestInstanceHeaderAloneSelectsTheInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	base := startZitadel(ctx, t)
	discovery := base + "/.well-known/openid-configuration"

	t.Run("the header selects the instance", func(t *testing.T) {
		code, body := get(ctx, t, discovery, serviceHost, publicHost)
		if code != http.StatusOK {
			t.Fatalf("GET with %s: %s = %d, want 200: %s", zitadelconn.InstanceHostHeader, publicHost, code, body)
		}
		if !strings.Contains(body, `"issuer":"https://`+publicHost+`"`) {
			t.Fatalf("the instance of %s must answer with its own issuer: %s", publicHost, body)
		}
	})
	t.Run("no header gets 404", func(t *testing.T) {
		code, body := get(ctx, t, discovery, serviceHost, "")
		if code != http.StatusNotFound {
			t.Fatalf("GET with no header = %d, want 404: %s", code, body)
		}
	})
}

// get sends one GET to url with the given Host header and instance header.
func get(ctx context.Context, t *testing.T, url, host, instanceHost string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = host
	if instanceHost != "" {
		req.Header.Set(zitadelconn.InstanceHostHeader, instanceHost)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// startZitadel starts Postgres and the pinned Zitadel on one network, and
// returns the base URL of Zitadel on the host. Zitadel serves plain HTTP
// behind an edge that terminates TLS (tlsMode external), as in the chart.
func startZitadel(ctx context.Context, t *testing.T) string {
	t.Helper()
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(context.Background()) })

	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          "postgres:17-alpine",
			Env:            map[string]string{"POSTGRES_PASSWORD": "postgres"},
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"db"}},
			WaitingFor:     wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })

	z, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: pinnedZitadelImage,
			Cmd:   []string{"start-from-init", "--masterkey", "MasterkeyNeedsToHave32Characters", "--tlsMode", "external"},
			Env: map[string]string{
				"ZITADEL_EXTERNALDOMAIN":                                 publicHost,
				"ZITADEL_EXTERNALPORT":                                   "443",
				"ZITADEL_EXTERNALSECURE":                                 "true",
				"ZITADEL_DATABASE_POSTGRES_HOST":                         "db",
				"ZITADEL_DATABASE_POSTGRES_PORT":                         "5432",
				"ZITADEL_DATABASE_POSTGRES_DATABASE":                     "zitadel",
				"ZITADEL_DATABASE_POSTGRES_USER_USERNAME":                "zitadel",
				"ZITADEL_DATABASE_POSTGRES_USER_PASSWORD":                "zitadel",
				"ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE":                "disable",
				"ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME":               "postgres",
				"ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD":               "postgres",
				"ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE":               "disable",
				"ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED": "false",
			},
			Networks:     []string{nw.Name},
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor: wait.ForHTTP("/debug/healthz").WithPort("8080/tcp").
				WithStartupTimeout(5 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start zitadel %s: %v", pinnedZitadelImage, err)
	}
	t.Cleanup(func() { _ = z.Terminate(context.Background()) })

	host, err := z.Host(ctx)
	if err != nil {
		t.Fatalf("zitadel host: %v", err)
	}
	port, err := z.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("zitadel port: %v", err)
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port())
}
