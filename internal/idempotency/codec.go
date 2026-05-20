package idempotency

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

// envelope is the JSON wire format of a cached response. We use JSON
// rather than a separately-generated protobuf message so the dedup
// store does not impose a new `make proto` rebuild step on every
// daemon change. The Response field is the protojson-encoded form of
// an Any so the proto-typed payload round-trips losslessly even
// though the envelope itself is JSON.
//
// Wire layout:
//
//	{
//	  "kind": "response" | "error",
//	  "response": "{...}",   // protojson(*anypb.Any) when kind=response
//	  "errCode": 7,           // int32 grpc codes.Code  when kind=error
//	  "errMsg":  "denied"     // string                 when kind=error
//	}
//
// We use a single JSON envelope rather than the bare protojson
// because terminal errors do not have a typed proto message of their
// own; embedding them inside a top-level JSON keeps both shapes in
// the same key.
type envelope struct {
	Kind     string `json:"kind"`
	Response string `json:"response,omitempty"`
	ErrCode  int32  `json:"errCode,omitempty"`
	ErrMsg   string `json:"errMsg,omitempty"`
}

const (
	kindResponse = "response"
	kindError    = "error"
)

func encodeEntry(c *CachedResponse) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("encodeEntry: nil CachedResponse")
	}
	if c.Response == nil && c.TerminalError == nil {
		return nil, fmt.Errorf("encodeEntry: both Response and TerminalError are nil")
	}
	if c.Response != nil && c.TerminalError != nil {
		return nil, fmt.Errorf("encodeEntry: both Response and TerminalError are set; expected exactly one")
	}
	env := envelope{}
	if c.Response != nil {
		raw, err := protojson.Marshal(c.Response)
		if err != nil {
			return nil, fmt.Errorf("encodeEntry: protojson.Marshal(Any): %w", err)
		}
		env.Kind = kindResponse
		env.Response = string(raw)
	} else {
		env.Kind = kindError
		env.ErrCode = c.TerminalError.Code
		env.ErrMsg = c.TerminalError.Message
	}
	return json.Marshal(env)
}

func decodeEntry(raw []byte) (*CachedResponse, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decodeEntry: json.Unmarshal: %w", err)
	}
	switch env.Kind {
	case kindResponse:
		if env.Response == "" {
			return nil, fmt.Errorf("decodeEntry: kind=response but no response payload")
		}
		any := &anypb.Any{}
		if err := protojson.Unmarshal([]byte(env.Response), any); err != nil {
			return nil, fmt.Errorf("decodeEntry: protojson.Unmarshal(Any): %w", err)
		}
		return &CachedResponse{Response: any}, nil
	case kindError:
		return &CachedResponse{
			TerminalError: &TerminalError{
				Code:    env.ErrCode,
				Message: env.ErrMsg,
			},
		}, nil
	default:
		return nil, fmt.Errorf("decodeEntry: unknown kind %q", env.Kind)
	}
}
