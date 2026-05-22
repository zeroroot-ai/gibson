// Package tenantfromctxviolation is a synthetic fixture for the
// tenantfromcontext analyzer. Each function reads req.TenantId without
// the gibsoncheck:allow tenant-from-request directive and must trigger
// a diagnostic at the read site.
package tenantfromctxviolation

import "context"

// Request is a stand-in for any gRPC request type carrying a TenantId.
type Request struct {
	TenantId string
}

// HandlerNoAllow reads req.TenantId without an opt-out.
func HandlerNoAllow(ctx context.Context, req *Request) error {
	if req.TenantId == "" { // want `req.TenantId is a request-body tenant read in handler code; tenant MUST come from auth.TenantFromContext\(ctx\) per Requirement 8.7`
		return nil
	}
	_ = req.TenantId // want `req.TenantId is a request-body tenant read`
	return nil
}

// HandlerCallerVar uses "request" instead of "req" — also flagged.
func HandlerCallerVar(ctx context.Context, request *Request) error {
	_ = request.TenantId // want `request.TenantId is a request-body tenant read`
	return nil
}
