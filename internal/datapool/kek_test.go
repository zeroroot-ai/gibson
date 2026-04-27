package datapool

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
)

func TestDeriveTenantKEK_Determinism(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0xAB}, 32)
	tenant := auth.MustNewTenantID("acme")

	kek1, err := deriveTenantKEK(masterKEK, tenant)
	require.NoError(t, err)
	require.Len(t, kek1, 32)

	kek2, err := deriveTenantKEK(masterKEK, tenant)
	require.NoError(t, err)

	assert.Equal(t, kek1, kek2, "same inputs must produce identical KEK")
}

func TestDeriveTenantKEK_DifferentTenants_DifferentKEKs(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0xCD}, 32)
	tenant1 := auth.MustNewTenantID("acme")
	tenant2 := auth.MustNewTenantID("bigcorp")

	kek1, err := deriveTenantKEK(masterKEK, tenant1)
	require.NoError(t, err)

	kek2, err := deriveTenantKEK(masterKEK, tenant2)
	require.NoError(t, err)

	assert.NotEqual(t, kek1, kek2, "different tenants must produce different KEKs")
}

func TestDeriveTenantKEK_DifferentMasterKEKs_DifferentOutputs(t *testing.T) {
	master1 := bytes.Repeat([]byte{0x01}, 32)
	master2 := bytes.Repeat([]byte{0x02}, 32)
	tenant := auth.MustNewTenantID("acme")

	kek1, err := deriveTenantKEK(master1, tenant)
	require.NoError(t, err)

	kek2, err := deriveTenantKEK(master2, tenant)
	require.NoError(t, err)

	assert.NotEqual(t, kek1, kek2, "different master KEKs must produce different tenant KEKs")
}

func TestDeriveTenantKEK_WeakMasterRejected(t *testing.T) {
	tests := []struct {
		name      string
		masterKEK []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"too short 16 bytes", bytes.Repeat([]byte{0xFF}, 16)},
		{"too short 31 bytes", bytes.Repeat([]byte{0xFF}, 31)},
	}
	tenant := auth.MustNewTenantID("acme")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := deriveTenantKEK(tc.masterKEK, tenant)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "too short")
		})
	}
}

func TestDeriveTenantKEK_ExactlyMinimumLength(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0xEE}, 32)
	tenant := auth.MustNewTenantID("acme")

	kek, err := deriveTenantKEK(masterKEK, tenant)
	require.NoError(t, err)
	assert.Len(t, kek, 32)
}

func TestDeriveTenantKEK_OutputLength(t *testing.T) {
	masterKEK := bytes.Repeat([]byte{0x77}, 64)
	tenant := auth.MustNewTenantID("testcorp")

	kek, err := deriveTenantKEK(masterKEK, tenant)
	require.NoError(t, err)
	assert.Len(t, kek, 32, "KEK must always be 32 bytes (AES-256)")
}
