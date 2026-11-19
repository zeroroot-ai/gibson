// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package finding

import (
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
)

// EvidenceTypeName returns the name that the SDK and the predicates of a
// Domain Pack use for an evidence type. The list of types is the enum
// types.v1.EvidenceType. This function and EvidenceTypeFromName are the only
// place in the daemon that maps between the enum and the names.
func EvidenceTypeName(t typespb.EvidenceType) sdkfinding.EvidenceType {
	switch t {
	case typespb.EvidenceType_EVIDENCE_TYPE_REQUEST:
		return sdkfinding.EvidenceHTTPRequest
	case typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE:
		return sdkfinding.EvidenceHTTPResponse
	case typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT:
		return sdkfinding.EvidenceScreenshot
	case typespb.EvidenceType_EVIDENCE_TYPE_CODE:
		return sdkfinding.EvidenceCodeSnippet
	case typespb.EvidenceType_EVIDENCE_TYPE_LOG:
		return sdkfinding.EvidenceLog
	case typespb.EvidenceType_EVIDENCE_TYPE_PAYLOAD:
		return sdkfinding.EvidencePayload
	case typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION:
		return sdkfinding.EvidenceConversation
	case typespb.EvidenceType_EVIDENCE_TYPE_NETWORK_TRACE:
		return sdkfinding.EvidenceNetworkTrace
	case typespb.EvidenceType_EVIDENCE_TYPE_UNSPECIFIED, typespb.EvidenceType_EVIDENCE_TYPE_OTHER:
		// These types have no name of their own. They map to the other type.
	}
	return sdkfinding.EvidenceOther
}

// EvidenceTypeFromName is the inverse of EvidenceTypeName. A name that is not
// in the list maps to EVIDENCE_TYPE_OTHER.
func EvidenceTypeFromName(n sdkfinding.EvidenceType) typespb.EvidenceType {
	switch n {
	case sdkfinding.EvidenceHTTPRequest:
		return typespb.EvidenceType_EVIDENCE_TYPE_REQUEST
	case sdkfinding.EvidenceHTTPResponse:
		return typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE
	case sdkfinding.EvidenceScreenshot:
		return typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT
	case sdkfinding.EvidenceCodeSnippet:
		return typespb.EvidenceType_EVIDENCE_TYPE_CODE
	case sdkfinding.EvidenceLog:
		return typespb.EvidenceType_EVIDENCE_TYPE_LOG
	case sdkfinding.EvidencePayload:
		return typespb.EvidenceType_EVIDENCE_TYPE_PAYLOAD
	case sdkfinding.EvidenceConversation:
		return typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION
	case sdkfinding.EvidenceNetworkTrace:
		return typespb.EvidenceType_EVIDENCE_TYPE_NETWORK_TRACE
	case sdkfinding.EvidenceOther:
		// The other type maps to EVIDENCE_TYPE_OTHER, as a name that is not in the list does.
	}
	return typespb.EvidenceType_EVIDENCE_TYPE_OTHER
}
