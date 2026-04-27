package datapool

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
)

// makeConnWithKEK builds a minimal Conn for release lifecycle tests.
func makeConnWithKEK(kek []byte, releaseFn func()) *Conn {
	return &Conn{
		Tenant:  auth.MustNewTenantID("testcorp"),
		KEK:     kek,
		release: releaseFn,
	}
}

func TestConn_Release_ZerosKEK(t *testing.T) {
	kek := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	require.Len(t, kek, 32)

	// Keep a reference to the backing array so we can inspect it after Release.
	backing := kek

	releaseCalled := false
	conn := makeConnWithKEK(kek, func() { releaseCalled = true })

	conn.Release()

	// KEK slice should be nil after Release.
	assert.Nil(t, conn.KEK, "conn.KEK must be nil after Release")

	// Every byte in the original backing array must be zero.
	for i, b := range backing {
		assert.Equal(t, byte(0), b, "KEK byte[%d] must be zero after Release", i)
	}

	assert.True(t, releaseCalled, "release func must be called")
}

func TestConn_Release_Idempotent(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = 0xFF
	}

	callCount := 0
	conn := makeConnWithKEK(kek, func() { callCount++ })

	// Should not panic on second call.
	conn.Release()
	conn.Release()
	conn.Release()

	// release func called exactly once despite multiple Release calls.
	assert.Equal(t, 1, callCount, "release func must be called exactly once")
	assert.Nil(t, conn.KEK)
}

func TestConn_Release_NilReleaseFn(t *testing.T) {
	kek := make([]byte, 16)
	for i := range kek {
		kek[i] = 0xAB
	}
	conn := makeConnWithKEK(kek, nil) // no release func

	// Must not panic when release func is nil.
	require.NotPanics(t, func() {
		conn.Release()
	})
	assert.Nil(t, conn.KEK)
}

func TestConn_Release_NilKEK(t *testing.T) {
	releaseCalled := false
	conn := makeConnWithKEK(nil, func() { releaseCalled = true })

	require.NotPanics(t, func() {
		conn.Release()
	})
	assert.Nil(t, conn.KEK)
	assert.True(t, releaseCalled)
}

func TestConn_Release_EmptyKEK(t *testing.T) {
	conn := makeConnWithKEK([]byte{}, func() {})
	require.NotPanics(t, func() {
		conn.Release()
	})
}

func TestAdminConn_Release_Idempotent(t *testing.T) {
	callCount := 0
	adminConn := &AdminConn{
		release: func() { callCount++ },
	}

	adminConn.Release()
	adminConn.Release()
	adminConn.Release()

	assert.Equal(t, 1, callCount, "AdminConn.Release must call release exactly once")
}

func TestZeroKEK(t *testing.T) {
	kek := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	backing := kek
	conn := &Conn{KEK: kek}
	zeroKEK(conn)
	assert.Nil(t, conn.KEK)
	for _, b := range backing {
		assert.Equal(t, byte(0), b)
	}
}
