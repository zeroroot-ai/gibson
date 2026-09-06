// Package tenantfromctxviolation is a synthetic fixture for the
// tenantfromcontext analyzer. Each function reads a tenant off the request
// without the gibsoncheck:allow tenant-from-request directive and must
// trigger a diagnostic at the read site — through the struct field AND
// through the generated Get* accessor.
package tenantfromctxviolation

import "context"

// Request is a stand-in for any gRPC request type carrying a TenantId.
type Request struct {
	TenantId string
}

// GetTenantId mirrors the accessor protoc-gen-go emits for every message.
func (r *Request) GetTenantId() string {
	if r == nil {
		return ""
	}
	return r.TenantId
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

// HandlerAccessor uses the generated accessor, which is what real handler
// code writes. Before this analyzer matched Get* names the whole class of
// request-body tenant reads was invisible here.
func HandlerAccessor(ctx context.Context, req *Request) error {
	tenantID := req.GetTenantId() // want `req.GetTenantId is a request-body tenant read`
	_ = tenantID
	return nil
}

// HandlerAccessorRenamedParam proves the check cannot be dodged by renaming
// the parameter away from the literal "req" / "request".
func HandlerAccessorRenamedParam(ctx context.Context, listReq *Request) error {
	_ = listReq.GetTenantId() // want `listReq.GetTenantId is a request-body tenant read`
	return nil
}

// serverStub stands in for a service receiver so the analyzer's receiver
// filter is exercised: s.GetTenantQuota is not a request-body read.
type serverStub struct{}

func (s *serverStub) GetTenantId() string { return "" }

// HandlerServerReceiver must NOT be flagged: the selector is on the server,
// not on an inbound request.
func HandlerServerReceiver(ctx context.Context, s *serverStub) error {
	_ = s.GetTenantId()
	return nil
}
