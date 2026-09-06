// Package tenantfromctxadmin is a synthetic fixture proving the analyzer
// covers internal/server/admin. That tree holds the MembershipService and
// TenantAdminService handlers and used to sit outside the analyzer's
// hardcoded package list entirely.
package tenantfromctxadmin

import "context"

// Request is a stand-in for any gRPC request type carrying a TenantId.
type Request struct {
	TenantId string
}

// GetTenantId mirrors the accessor protoc-gen-go emits.
func (r *Request) GetTenantId() string {
	if r == nil {
		return ""
	}
	return r.TenantId
}

// SetTenantRole is the shape of the worst offender in this package: the
// request tenant selects the FGA object the role tuple is written against.
func SetTenantRole(ctx context.Context, req *Request) error {
	tenantRef := "tenant:" + req.GetTenantId() // want `req.GetTenantId is a request-body tenant read`
	_ = tenantRef
	return nil
}
