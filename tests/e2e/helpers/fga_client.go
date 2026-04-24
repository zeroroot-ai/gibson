//go:build e2e
// +build e2e

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// FGAClient is a minimal OpenFGA HTTP API client.  It uses only stdlib — no
// openfga/go-sdk dependency.  All token/tuple values are kept out of log
// output by design (Requirement 7: Security).
type FGAClient struct {
	baseURL  string       // e.g. "http://gibson-fga:8080"
	storeID  string       // the FGA store ID
	httpClient *http.Client
}

// NewFGAClient creates a new FGAClient.  If storeID is empty it must be set
// later with LoadStoreIDFromCluster.
func NewFGAClient(baseURL, storeID string) *FGAClient {
	return &FGAClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		storeID: storeID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// LoadStoreIDFromCluster reads the FGA store ID from the `gibson-fga-config`
// ConfigMap in the gibson namespace.  Call this after creating the client if
// you don't know the store ID up front.
func (c *FGAClient) LoadStoreIDFromCluster(ctx context.Context, kubeClient kubernetes.Interface) error {
	cm, err := kubeClient.CoreV1().ConfigMaps("gibson").Get(ctx, "gibson-fga-config", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("fga_client: get gibson-fga-config configmap: %w", err)
	}
	storeID, ok := cm.Data["store_id"]
	if !ok || storeID == "" {
		return fmt.Errorf("fga_client: gibson-fga-config has no store_id key")
	}
	c.storeID = storeID
	return nil
}

// fgaTupleKey is the JSON shape used in FGA's /check and /read requests.
type fgaTupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

// fgaCheckRequest is the body sent to POST /stores/<id>/check.
type fgaCheckRequest struct {
	TupleKey fgaTupleKey `json:"tuple_key"`
}

// fgaCheckResponse is the body returned by POST /stores/<id>/check.
type fgaCheckResponse struct {
	Allowed bool `json:"allowed"`
}

// Check calls the FGA Check API endpoint and returns whether the given
// user has the given relation on the given object.
//
// user, relation, object use the FGA string format:
//   - user:   "user:alice@example.com"
//   - relation: "admin"
//   - object: "tenant:my-slug"
//
// Requirements: R1.6, R7.4.
// Bug catalog: B6 (SPIFFE prefix in user string), B8 (fga-init silent error),
// B9 (wrong FGA address).
func (c *FGAClient) Check(ctx context.Context, user, relation, object string) (bool, error) {
	if c.storeID == "" {
		return false, fmt.Errorf("fga_client: store ID not set — call LoadStoreIDFromCluster first")
	}
	body := fgaCheckRequest{TupleKey: fgaTupleKey{User: user, Relation: relation, Object: object}}
	b, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/stores/%s/check", c.baseURL, c.storeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return false, fmt.Errorf("fga_client: build check request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("fga_client: POST %s: %w — B9: check that EXT_AUTHZ_FGA_ADDR and the test's fgaURL both point to gibson-fga:8080 (HTTP, not gRPC 8081)", url, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("fga_client: check returned HTTP %d: %s", resp.StatusCode, string(rawBody))
	}
	var checkResp fgaCheckResponse
	if err := json.Unmarshal(rawBody, &checkResp); err != nil {
		return false, fmt.Errorf("fga_client: unmarshal check response: %w", err)
	}
	return checkResp.Allowed, nil
}

// fgaReadRequest is the body sent to POST /stores/<id>/read.
type fgaReadRequest struct {
	TupleKey fgaTupleKey `json:"tuple_key"`
}

// Tuple mirrors one tuple returned by the FGA /read endpoint.
type Tuple struct {
	Key fgaTupleKey `json:"key"`
}

// fgaReadResponse is the body returned by POST /stores/<id>/read.
type fgaReadResponse struct {
	Tuples []struct {
		Key fgaTupleKey `json:"key"`
	} `json:"tuples"`
}

// Read queries the FGA store for tuples matching the given partial key.
// Any field left as empty string acts as a wildcard.
//
// Requirements: R1.6.
// Bug catalog: B7 (wrong relation — Read won't find admin tuple if relation is platform_operator).
func (c *FGAClient) Read(ctx context.Context, user, relation, object string) ([]Tuple, error) {
	if c.storeID == "" {
		return nil, fmt.Errorf("fga_client: store ID not set")
	}
	body := fgaReadRequest{TupleKey: fgaTupleKey{User: user, Relation: relation, Object: object}}
	b, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/stores/%s/read", c.baseURL, c.storeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("fga_client: build read request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fga_client: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fga_client: read returned HTTP %d: %s", resp.StatusCode, string(rawBody))
	}
	var readResp fgaReadResponse
	if err := json.Unmarshal(rawBody, &readResp); err != nil {
		return nil, fmt.Errorf("fga_client: unmarshal read response: %w", err)
	}
	tuples := make([]Tuple, len(readResp.Tuples))
	for i, t := range readResp.Tuples {
		tuples[i] = Tuple{Key: t.Key}
	}
	return tuples, nil
}

// MustHavePlatformOperator asserts that the FGA store contains the seed tuple:
//
//	user:gibson.io/platform/dashboard → platform_operator → system_tenant:_system
//
// This tuple is seeded by the `gibson-fga-init` Job on helm install/upgrade.
// Its absence means either B8 (job silently failed) or the fga-init Job was
// never applied.
//
// dashboardSPIFFE is the SPIFFE ID of the dashboard workload, e.g.
// "gibson.io/platform/dashboard" (without the "spiffe://" prefix, because
// FGA rejects the `://` separator — bug B6).
//
// Requirements: R7.4.
// Bug catalog: B7 (wrong relation), B8 (fga-init silent error).
func MustHavePlatformOperator(t interface{ Fatalf(string, ...interface{}) },
	ctx context.Context, fgaClient *FGAClient, dashboardSPIFFE string) {

	// FGA user format strips the spiffe:// scheme (B6 fix).
	user := "user:" + dashboardSPIFFE

	tuples, err := fgaClient.Read(ctx, user, "platform_operator", "system_tenant:_system")
	if err != nil {
		t.Fatalf(
			"MustHavePlatformOperator: FGA Read failed: %v\n"+
				"Bug catalog: B8 (fga-init may have silently swallowed the error), "+
				"B9 (wrong FGA endpoint — check EXT_AUTHZ_FGA_ADDR points to gibson-fga:8080)",
			err,
		)
		return
	}
	if len(tuples) == 0 {
		t.Fatalf(
			"MustHavePlatformOperator: no platform_operator tuple found for dashboard SPIFFE %q on system_tenant:_system\n"+
				"Bug catalog: B8 (fga-init job's catch-all swallowed the seeding error), "+
				"B7 (init-job may have used the wrong relation)",
			dashboardSPIFFE,
		)
	}
}
