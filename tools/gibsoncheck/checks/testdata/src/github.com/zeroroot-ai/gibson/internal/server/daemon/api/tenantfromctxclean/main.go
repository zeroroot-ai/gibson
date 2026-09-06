// Package tenantfromctxclean is a synthetic fixture for the
// tenantfromcontext analyzer. Both functions read req.TenantId but each
// carries the gibsoncheck:allow tenant-from-request directive in its
// doc comment. The analyzer MUST emit zero diagnostics against this
// package.
package tenantfromctxclean

import "context"

// Request is a stand-in for any gRPC request type carrying a TenantId.
type Request struct {
	TenantId string
}

// AdminImpersonate is an admin RPC that takes the target tenant in the
// request body; the platform_operator FGA relation enforces authorization.
//
// gibsoncheck:allow tenant-from-request
func AdminImpersonate(ctx context.Context, req *Request) error {
	if req.TenantId == "" {
		return nil
	}
	_ = req.TenantId
	return nil
}

// AdminTenantAdmin is a TenantAdminService RPC; the inline cross-tenant
// guard plus the FGA tenant_admin relation cover the cross-tenant case.
//
// gibsoncheck:allow tenant-from-request
func AdminTenantAdmin(ctx context.Context, req *Request) error {
	_ = req.TenantId
	return nil
}

// GetTenantId mirrors the accessor protoc-gen-go emits for every message.
func (r *Request) GetTenantId() string {
	if r == nil {
		return ""
	}
	return r.TenantId
}

// AdminAccessorSuppressed proves the directive also suppresses the accessor
// form, so an admin-gated handler can keep reading the supplied tenant.
//
// gibsoncheck:allow tenant-from-request (guarded by requireTenantAdmin)
func AdminAccessorSuppressed(ctx context.Context, req *Request) error {
	_ = req.GetTenantId()
	return nil
}
