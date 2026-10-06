package component

import (
	"context"
	"log/slog"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scanRecord struct {
	Name string `json:"name"`
}

func newScanClient(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client, mr
}

// A record that does not decode is skipped. The other records return.
func TestScanJSONRecords_SkipsARecordThatDoesNotDecode(t *testing.T) {
	client, mr := newScanClient(t)
	require.NoError(t, mr.Set("rec:a", `{"name":"a"}`))
	require.NoError(t, mr.Set("rec:b", `not json`))

	got, err := scanJSONRecords[scanRecord](context.Background(), client, "rec:*", "test record")
	require.NoError(t, err)
	assert.Equal(t, []scanRecord{{Name: "a"}}, got)
}

// A key that holds the wrong Redis type stops the scan with an error.
func TestScanJSONRecords_WrongTypeKey_ReturnsError(t *testing.T) {
	client, mr := newScanClient(t)
	mr.HSet("rec:h", "f", "v")

	got, err := scanJSONRecords[scanRecord](context.Background(), client, "rec:*", "test record")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get test record rec:h")
	assert.Nil(t, got)
}

// A scan with no match returns no records and no error.
func TestScanJSONRecords_NoMatch_ReturnsEmpty(t *testing.T) {
	client, _ := newScanClient(t)

	got, err := scanJSONRecords[scanRecord](context.Background(), client, "rec:*", "test record")
	require.NoError(t, err)
	assert.Empty(t, got)
}

// ListTenantTools returns the tools of one tenant only.
func TestToolAccessStore_ListTenantTools_ReturnsTheToolsOfTheTenant(t *testing.T) {
	client, _ := newScanClient(t)
	store := NewRedisToolAccessStore(client, slog.New(slog.DiscardHandler))
	ctx := context.Background()
	require.NoError(t, store.Enable(ctx, "tenant-a", "nmap", "admin"))
	require.NoError(t, store.Enable(ctx, "tenant-b", "nuclei", "admin"))

	got, err := store.ListTenantTools(ctx, "tenant-a")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "nmap", got[0].ToolName)
}
