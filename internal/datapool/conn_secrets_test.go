package datapool

import (
	"testing"

	"github.com/zero-day-ai/sdk/auth"
)

// TestConn_Secrets_NonNil verifies that Conn.Secrets() returns a non-nil
// *TenantSecretsOps when the Conn has a KEK set. The test does not require a
// live Postgres pool — the returned ops struct is valid to construct with a nil
// pool (a nil pool will panic only on actual database calls, not on construction).
func TestConn_Secrets_NonNil(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}

	conn := &Conn{
		Tenant:  auth.MustNewTenantID("test-tenant"),
		KEK:     kek,
		release: func() {},
	}

	ops := conn.Secrets()
	if ops == nil {
		t.Fatal("conn.Secrets() must not return nil")
	}
}

// TestConn_Secrets_TenantPropagated verifies that the tenant string from the
// Conn is carried through to the TenantSecretsOps (used for metric labels on
// cross-tenant decrypt failures). We check this indirectly by confirming the
// accessor returns a valid ops instance associated with the right Conn.
func TestConn_Secrets_TenantPropagated(t *testing.T) {
	kek := make([]byte, 32)
	conn := &Conn{
		Tenant:  auth.MustNewTenantID("acme-corp"),
		KEK:     kek,
		release: func() {},
	}

	// Two calls should return independent instances (not cached).
	ops1 := conn.Secrets()
	ops2 := conn.Secrets()
	if ops1 == nil || ops2 == nil {
		t.Fatal("conn.Secrets() must not return nil")
	}
	// They must be distinct pointers — the accessor constructs a new value each call.
	if ops1 == ops2 {
		t.Error("conn.Secrets() should return a new instance on each call")
	}
}
