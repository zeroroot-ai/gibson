//go:build e2e
// +build e2e

// Package helpers — fixture_deployer.go
//
// Idempotent deployment and teardown of the mission e2e test fixtures:
//   - probe agent (tests/e2e/fixtures/agents/probe/manifest.yaml)
//   - test-target HTTP server (tests/e2e/fixtures/targets/test-target/manifest.yaml)
//
// Uses the Kubernetes dynamic client to apply/delete manifests and
// wait.PollUntilContextTimeout for Ready-wait — no raw time.Sleep.
//
// Design Component 5 / Requirements: R2.1, R2.2, R2.3, R7.4, NFR Reliability.
package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	daemonpb "github.com/zero-day-ai/sdk/api/gen/gibson/daemon/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	// FixtureNamespace is the Kubernetes namespace where test fixtures are deployed.
	FixtureNamespace = "gibson"

	// FixtureReadyDeadline is the maximum time to wait for fixtures to be Ready.
	FixtureReadyDeadline = 90 * time.Second

	// ProbeAgentRegistryDeadline is the maximum time to wait for the probe agent
	// to appear in the daemon's component registry.
	ProbeAgentRegistryDeadline = 60 * time.Second
)

// FixtureManifestPaths returns the absolute paths of the fixture manifests
// relative to the repository root. Reads REPO_ROOT env var if set; otherwise
// infers from the test binary location (for Kind/CI environments).
func FixtureManifestPaths() (probeManifest, targetManifest string, err error) {
	root := os.Getenv("REPO_ROOT")
	if root == "" {
		// Try to infer from current working directory (typically the repo root in CI).
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return "", "", fmt.Errorf("fixture_deployer: FixtureManifestPaths: get cwd: %w", cwdErr)
		}
		root = cwd
	}
	probe := filepath.Join(root, "core/gibson/tests/e2e/fixtures/agents/probe/manifest.yaml")
	target := filepath.Join(root, "core/gibson/tests/e2e/fixtures/targets/test-target/manifest.yaml")
	return probe, target, nil
}

// DeployTestFixtures applies the probe agent + test-target manifests and waits
// for both pods to be Ready.
//
// Idempotent: tolerates AlreadyExists on apply.
// No raw time.Sleep: uses wait.PollUntilContextTimeout.
//
// Requirements: R2.1, R2.2, NFR Reliability.
func DeployTestFixtures(ctx context.Context, kubeClient kubernetes.Interface, dynClient dynamic.Interface) error {
	probeManifest, targetManifest, err := FixtureManifestPaths()
	if err != nil {
		return fmt.Errorf("fixture_deployer: DeployTestFixtures: %w", err)
	}

	for _, path := range []string{probeManifest, targetManifest} {
		if applyErr := applyManifest(ctx, dynClient, path); applyErr != nil {
			return fmt.Errorf("fixture_deployer: DeployTestFixtures: apply %s: %w", path, applyErr)
		}
	}

	// Wait for both deployments to be Available / pods to be Ready.
	if waitErr := waitForFixturePodsReady(ctx, kubeClient, FixtureReadyDeadline); waitErr != nil {
		return fmt.Errorf("fixture_deployer: DeployTestFixtures: wait for Ready: %w", waitErr)
	}
	return nil
}

// TeardownTestFixtures deletes the probe agent + test-target fixtures.
// Best-effort: tolerates NotFound, logs errors but does not return them.
//
// Requirements: R1.10, NFR Reliability.
func TeardownTestFixtures(ctx context.Context, t *testing.T, dynClient dynamic.Interface) {
	t.Helper()
	probeManifest, targetManifest, err := FixtureManifestPaths()
	if err != nil {
		t.Logf("fixture_deployer: TeardownTestFixtures: could not resolve manifest paths: %v", err)
		return
	}

	for _, path := range []string{probeManifest, targetManifest} {
		if delErr := deleteManifest(ctx, dynClient, path); delErr != nil {
			t.Logf("fixture_deployer: TeardownTestFixtures: delete %s: %v (best-effort, continuing)", path, delErr)
		}
	}
	t.Log("fixture_deployer: TeardownTestFixtures: complete (best-effort)")
}

// WaitForProbeAgentRegistered polls the daemon's component registry until the
// "probe" agent appears in the list, or the deadline elapses.
//
// Uses wait.PollUntilContextTimeout — no raw time.Sleep.
//
// Requirements: R2.3.
func WaitForProbeAgentRegistered(ctx context.Context, client daemonpb.DaemonServiceClient, deadline time.Duration) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	return wait.PollUntilContextTimeout(
		deadlineCtx,
		2*time.Second,
		deadline,
		true, // immediate first poll
		func(pollCtx context.Context) (done bool, err error) {
			resp, listErr := client.ListAgents(pollCtx, &daemonpb.ListAgentsRequest{})
			if listErr != nil {
				// Transient error — retry.
				return false, nil
			}
			for _, agent := range resp.GetAgents() {
				kind := strings.ToLower(agent.GetKind())
				name := strings.ToLower(agent.GetName())
				if kind == "probe" || name == "probe" || strings.Contains(name, "probe") {
					return true, nil // probe agent is registered
				}
			}
			return false, nil
		},
	)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// applyManifest reads a YAML file containing one or more Kubernetes resource
// definitions and applies them to the cluster via the dynamic client.
// Tolerates AlreadyExists (idempotent).
func applyManifest(ctx context.Context, dynClient dynamic.Interface, manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("applyManifest: read %s: %w", manifestPath, err)
	}

	// Split on "---" separators (multi-document YAML).
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var rawObj map[string]interface{}
		decErr := decoder.Decode(&rawObj)
		if decErr == io.EOF {
			break
		}
		if decErr != nil {
			return fmt.Errorf("applyManifest: decode %s: %w", manifestPath, decErr)
		}
		if len(rawObj) == 0 {
			continue
		}

		obj := &unstructured.Unstructured{Object: rawObj}

		// Resolve GVR from the object's apiVersion + kind.
		gvr, gvrErr := gvrForObject(obj)
		if gvrErr != nil {
			return fmt.Errorf("applyManifest: resolve GVR for %s/%s: %w", obj.GetKind(), obj.GetName(), gvrErr)
		}

		ns := obj.GetNamespace()
		if ns == "" {
			ns = FixtureNamespace
			obj.SetNamespace(ns)
		}

		// Try create first; if AlreadyExists, update (server-side apply would be
		// cleaner but not available in all client-go versions).
		_, createErr := dynClient.Resource(gvr).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
		if createErr != nil {
			if apierrors.IsAlreadyExists(createErr) {
				// Update the existing resource.
				existing, getErr := dynClient.Resource(gvr).Namespace(ns).Get(ctx, obj.GetName(), metav1.GetOptions{})
				if getErr != nil {
					return fmt.Errorf("applyManifest: get existing %s/%s: %w", obj.GetKind(), obj.GetName(), getErr)
				}
				obj.SetResourceVersion(existing.GetResourceVersion())
				if _, updateErr := dynClient.Resource(gvr).Namespace(ns).Update(ctx, obj, metav1.UpdateOptions{}); updateErr != nil {
					return fmt.Errorf("applyManifest: update %s/%s: %w", obj.GetKind(), obj.GetName(), updateErr)
				}
			} else {
				return fmt.Errorf("applyManifest: create %s/%s: %w", obj.GetKind(), obj.GetName(), createErr)
			}
		}
	}
	return nil
}

// deleteManifest reads a YAML manifest and deletes each resource.
// Tolerates NotFound.
func deleteManifest(ctx context.Context, dynClient dynamic.Interface, manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // manifest doesn't exist locally; nothing to delete
		}
		return fmt.Errorf("deleteManifest: read %s: %w", manifestPath, err)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var errs []string
	for {
		var rawObj map[string]interface{}
		decErr := decoder.Decode(&rawObj)
		if decErr == io.EOF {
			break
		}
		if decErr != nil {
			errs = append(errs, fmt.Sprintf("decode: %v", decErr))
			continue
		}
		if len(rawObj) == 0 {
			continue
		}

		obj := &unstructured.Unstructured{Object: rawObj}
		gvr, gvrErr := gvrForObject(obj)
		if gvrErr != nil {
			errs = append(errs, fmt.Sprintf("GVR for %s/%s: %v", obj.GetKind(), obj.GetName(), gvrErr))
			continue
		}

		ns := obj.GetNamespace()
		if ns == "" {
			ns = FixtureNamespace
		}

		delErr := dynClient.Resource(gvr).Namespace(ns).Delete(ctx, obj.GetName(), metav1.DeleteOptions{})
		if delErr != nil && !apierrors.IsNotFound(delErr) {
			errs = append(errs, fmt.Sprintf("delete %s/%s: %v", obj.GetKind(), obj.GetName(), delErr))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("deleteManifest: %s: %s", manifestPath, strings.Join(errs, "; "))
	}
	return nil
}

// waitForFixturePodsReady polls until pods labeled app=probe and app=test-target
// are both Running/Ready in the FixtureNamespace.
func waitForFixturePodsReady(ctx context.Context, kubeClient kubernetes.Interface, deadline time.Duration) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	labels := []string{"app=probe", "app=test-target"}

	for _, label := range labels {
		label := label // capture loop variable
		waitErr := wait.PollUntilContextTimeout(
			deadlineCtx,
			3*time.Second,
			deadline,
			true,
			func(pollCtx context.Context) (done bool, err error) {
				pods, listErr := kubeClient.CoreV1().Pods(FixtureNamespace).List(pollCtx, metav1.ListOptions{
					LabelSelector: label,
				})
				if listErr != nil {
					return false, nil // transient error, retry
				}
				if len(pods.Items) == 0 {
					return false, nil // pod not created yet
				}
				for _, pod := range pods.Items {
					if pod.Status.Phase != "Running" {
						return false, nil
					}
					for _, cond := range pod.Status.Conditions {
						if cond.Type == "Ready" && cond.Status == "True" {
							return true, nil
						}
					}
				}
				return false, nil
			},
		)
		if waitErr != nil {
			return fmt.Errorf("waitForFixturePodsReady: label=%s deadline=%s: %w", label, deadline, waitErr)
		}
	}
	return nil
}

// gvrForObject maps an Unstructured object's apiVersion+kind to a GVR for the
// dynamic client. Supports the resource types used by the fixture manifests.
func gvrForObject(obj *unstructured.Unstructured) (schema.GroupVersionResource, error) {
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()

	// apiVersion is "group/version" or just "version" for core types.
	parts := strings.SplitN(apiVersion, "/", 2)
	var group, version string
	if len(parts) == 2 {
		group = parts[0]
		version = parts[1]
	} else {
		group = ""
		version = parts[0]
	}

	// Map kind → plural resource name.
	resource, err := kindToResource(kind)
	if err != nil {
		return schema.GroupVersionResource{}, err
	}

	return schema.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}, nil
}

// kindToResource returns the lowercase plural resource name for a given Kind.
// Only covers the resource types used by the fixture manifests.
func kindToResource(kind string) (string, error) {
	switch strings.ToLower(kind) {
	case "deployment":
		return "deployments", nil
	case "service":
		return "services", nil
	case "serviceaccount":
		return "serviceaccounts", nil
	case "configmap":
		return "configmaps", nil
	case "job":
		return "jobs", nil
	case "pod":
		return "pods", nil
	case "namespace":
		return "namespaces", nil
	default:
		return "", fmt.Errorf("kindToResource: unsupported kind %q (add it to fixture_deployer.go)", kind)
	}
}

// RegisterTestTarget inserts a test target record directly into the daemon's Redis
// targetStore so that RunMission / CreateMission can reference it by UUID.
//
// Background: Gibson has no public gRPC CreateTarget RPC. Targets are created through
// the dashboard or by operators. For e2e tests we write the minimal target document
// directly using the same Redis key convention as internal/database/RedisTargetDAO:
//   - Document:    gibson:target:{uuid}
//   - Name lookup: gibson:target:by_name:{name}
//
// The function reads REDIS_ADDR env var (default: "localhost:6379") to connect.
// It returns the assigned target UUID string.
//
// This is intentionally a test-only path — it writes directly to Redis.
// Requirements: R2.2, R1.4.
func RegisterTestTarget(ctx context.Context, name, targetURL string) (string, error) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return "", fmt.Errorf("fixture_deployer: RegisterTestTarget: ping Redis %s: %w", redisAddr, err)
	}

	targetID := uuid.New().String()
	now := time.Now().UnixMilli()

	doc := map[string]interface{}{
		"id":         targetID,
		"name":       name,
		"type":       "web",
		"url":        targetURL,
		"status":     "active",
		"created_at": now,
		"updated_at": now,
		"connection": map[string]interface{}{
			"url": targetURL,
		},
		"tags": []string{"e2e", "test-fixture"},
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("fixture_deployer: RegisterTestTarget: marshal target doc: %w", err)
	}

	// Write document at gibson:target:{id}
	docKey := fmt.Sprintf("gibson:target:%s", targetID)
	if err := rdb.Set(ctx, docKey, docJSON, 0).Err(); err != nil {
		return "", fmt.Errorf("fixture_deployer: RegisterTestTarget: write target doc to Redis: %w", err)
	}

	// Write name lookup at gibson:target:by_name:{name}
	nameKey := fmt.Sprintf("gibson:target:by_name:%s", name)
	if err := rdb.Set(ctx, nameKey, targetID, 0).Err(); err != nil {
		return "", fmt.Errorf("fixture_deployer: RegisterTestTarget: write target name lookup to Redis: %w", err)
	}

	return targetID, nil
}

// DeleteTestTarget removes a test target from Redis by UUID.
// Tolerates missing keys — idempotent.
// Requirements: R1.10.
func DeleteTestTarget(ctx context.Context, targetID, name string) {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()

	_ = rdb.Del(ctx, fmt.Sprintf("gibson:target:%s", targetID))
	_ = rdb.Del(ctx, fmt.Sprintf("gibson:target:by_name:%s", name))
}

// EncodeFixtureCoordFile writes the mission coordination file for the Playwright spec.
// Path: /tmp/mission-run-<slug>.json
//
// Requirements: R5 (Playwright spec reads this file).
func EncodeFixtureCoordFile(slug string, missionID string, findings []MissionFinding) error {
	type coordFile struct {
		MissionID string          `json:"mission_id"`
		Slug      string          `json:"slug"`
		Findings  []MissionFinding `json:"findings"`
	}
	data, err := json.MarshalIndent(coordFile{
		MissionID: missionID,
		Slug:      slug,
		Findings:  findings,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("fixture_deployer: EncodeFixtureCoordFile: marshal: %w", err)
	}
	path := fmt.Sprintf("/tmp/mission-run-%s.json", slug)
	if writeErr := os.WriteFile(path, data, 0644); writeErr != nil { //nolint:gosec // test artifact only
		return fmt.Errorf("fixture_deployer: EncodeFixtureCoordFile: write %s: %w", path, writeErr)
	}
	return nil
}
