package types

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestNewID(t *testing.T) {
	t.Run("generates valid UUID", func(t *testing.T) {
		id := NewID()

		if id.IsZero() {
			t.Error("NewID() returned zero value")
		}

		if err := id.Validate(); err != nil {
			t.Errorf("NewID() generated invalid ID: %v", err)
		}

		// Verify it's a valid UUID format
		_, err := uuid.Parse(string(id))
		if err != nil {
			t.Errorf("NewID() generated invalid UUID: %v", err)
		}
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		id1 := NewID()
		id2 := NewID()

		if id1 == id2 {
			t.Error("NewID() generated duplicate IDs")
		}
	})
}

func TestParseID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid UUID v4",
			input:   "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "valid UUID v1",
			input:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid format - not a UUID",
			input:   "not-a-uuid",
			wantErr: true,
		},
		{
			name:    "invalid format - partial UUID",
			input:   "550e8400-e29b-41d4",
			wantErr: true,
		},
		{
			name:    "invalid format - wrong characters",
			input:   "550e8400-e29b-41d4-a716-44665544000g",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseID(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseID() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseID() unexpected error: %v", err)
				return
			}

			if id.IsZero() {
				t.Error("ParseID() returned zero value for valid input")
			}

			// Verify the parsed ID is normalized (lowercase, hyphenated)
			expectedUUID, _ := uuid.Parse(tt.input)
			if id.String() != expectedUUID.String() {
				t.Errorf("ParseID() = %v, want %v", id.String(), expectedUUID.String())
			}
		})
	}
}

func TestID_Validate(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		wantErr bool
	}{
		{
			name:    "valid UUID",
			id:      ID("550e8400-e29b-41d4-a716-446655440000"),
			wantErr: false,
		},
		{
			name:    "empty ID",
			id:      ID(""),
			wantErr: true,
		},
		{
			name:    "invalid UUID format",
			id:      ID("not-a-uuid"),
			wantErr: true,
		},
		{
			name:    "partial UUID",
			id:      ID("550e8400-e29b"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()

			if tt.wantErr && err == nil {
				t.Error("Validate() expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestID_String(t *testing.T) {
	t.Run("returns string representation", func(t *testing.T) {
		expectedUUID := "550e8400-e29b-41d4-a716-446655440000"
		id := ID(expectedUUID)

		result := id.String()

		if result != expectedUUID {
			t.Errorf("String() = %v, want %v", result, expectedUUID)
		}
	})

	t.Run("returns empty string for zero value", func(t *testing.T) {
		var id ID

		result := id.String()

		if result != "" {
			t.Errorf("String() = %v, want empty string", result)
		}
	})
}

func TestID_IsZero(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want bool
	}{
		{
			name: "zero value",
			id:   ID(""),
			want: true,
		},
		{
			name: "non-zero value",
			id:   ID("550e8400-e29b-41d4-a716-446655440000"),
			want: false,
		},
		{
			name: "uninitialized ID",
			id:   ID(""),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestID_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		want    string
		wantErr bool
	}{
		{
			name: "valid UUID",
			id:   ID("550e8400-e29b-41d4-a716-446655440000"),
			want: `"550e8400-e29b-41d4-a716-446655440000"`,
		},
		{
			name: "zero value",
			id:   ID(""),
			want: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.id.MarshalJSON()

			if tt.wantErr && err == nil {
				t.Error("MarshalJSON() expected error but got none")
				return
			}

			if !tt.wantErr && err != nil {
				t.Errorf("MarshalJSON() unexpected error: %v", err)
				return
			}

			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %v, want %v", string(got), tt.want)
			}
		})
	}

	t.Run("marshal in struct", func(t *testing.T) {
		type TestStruct struct {
			ID ID `json:"id"`
		}

		testID := NewID()
		s := TestStruct{ID: testID}

		data, err := json.Marshal(s)
		if err != nil {
			t.Errorf("json.Marshal() error: %v", err)
			return
		}

		var decoded TestStruct
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Errorf("json.Unmarshal() error: %v", err)
			return
		}

		if decoded.ID != testID {
			t.Errorf("Round-trip marshal/unmarshal failed: got %v, want %v", decoded.ID, testID)
		}
	})
}

func TestID_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantID  string
		wantErr bool
	}{
		{
			name:   "valid UUID",
			input:  `"550e8400-e29b-41d4-a716-446655440000"`,
			wantID: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:   "empty string",
			input:  `""`,
			wantID: "",
		},
		{
			name:   "null value",
			input:  `null`,
			wantID: "",
		},
		{
			name:    "invalid UUID format",
			input:   `"not-a-uuid"`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "number instead of string",
			input:   `123`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id ID
			err := id.UnmarshalJSON([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalJSON() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error: %v", err)
				return
			}

			if id.String() != tt.wantID {
				t.Errorf("UnmarshalJSON() = %v, want %v", id.String(), tt.wantID)
			}
		})
	}

	t.Run("unmarshal in struct", func(t *testing.T) {
		type TestStruct struct {
			ID ID `json:"id"`
		}

		jsonData := `{"id":"550e8400-e29b-41d4-a716-446655440000"}`

		var s TestStruct
		if err := json.Unmarshal([]byte(jsonData), &s); err != nil {
			t.Errorf("json.Unmarshal() error: %v", err)
			return
		}

		expectedID := ID("550e8400-e29b-41d4-a716-446655440000")
		if s.ID != expectedID {
			t.Errorf("UnmarshalJSON() in struct: got %v, want %v", s.ID, expectedID)
		}

		if err := s.ID.Validate(); err != nil {
			t.Errorf("Unmarshaled ID is invalid: %v", err)
		}
	})
}

// TestID_RoundTrip tests the complete marshal/unmarshal cycle
func TestID_RoundTrip(t *testing.T) {
	t.Run("round trip preserves ID", func(t *testing.T) {
		original := NewID()

		// Marshal
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		// Unmarshal
		var decoded ID
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		// Compare
		if decoded != original {
			t.Errorf("Round trip failed: got %v, want %v", decoded, original)
		}

		if err := decoded.Validate(); err != nil {
			t.Errorf("Round-tripped ID is invalid: %v", err)
		}
	})
}
