package types

import (
	"encoding/json"
	"testing"
)

func BenchmarkNewID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewID()
	}
}

func BenchmarkParseID(b *testing.B) {
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseID(validUUID)
	}
}

func BenchmarkID_Validate(b *testing.B) {
	id := NewID()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Validate()
	}
}

func BenchmarkID_MarshalJSON(b *testing.B) {
	id := NewID()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = id.MarshalJSON()
	}
}

func BenchmarkID_UnmarshalJSON(b *testing.B) {
	data := []byte(`"550e8400-e29b-41d4-a716-446655440000"`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var id ID
		_ = id.UnmarshalJSON(data)
	}
}

func BenchmarkID_JSONRoundTrip(b *testing.B) {
	type TestStruct struct {
		ID ID `json:"id"`
	}
	original := TestStruct{ID: NewID()}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := json.Marshal(original)
		var decoded TestStruct
		_ = json.Unmarshal(data, &decoded)
	}
}
