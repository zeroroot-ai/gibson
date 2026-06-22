package types_test

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ExampleNewID demonstrates generating a new UUID-based ID
func ExampleNewID() {
	id := types.NewID()
	fmt.Println("Generated ID length:", len(id.String()))
	// Output: Generated ID length: 36
}

// ExampleParseID demonstrates parsing a UUID string into an ID
func ExampleParseID() {
	id, err := types.ParseID("550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Parsed ID:", id.String())
	// Output: Parsed ID: 550e8400-e29b-41d4-a716-446655440000
}

// ExampleParseID_invalid demonstrates error handling for invalid UUIDs
func ExampleParseID_invalid() {
	_, err := types.ParseID("not-a-valid-uuid")
	if err != nil {
		fmt.Println("Error parsing invalid UUID")
	}
	// Output: Error parsing invalid UUID
}

// ExampleID_Validate demonstrates validating an ID
func ExampleID_Validate() {
	id, _ := types.ParseID("550e8400-e29b-41d4-a716-446655440000")
	if err := id.Validate(); err != nil {
		fmt.Println("Invalid ID:", err)
		return
	}
	fmt.Println("ID is valid")
	// Output: ID is valid
}

// ExampleID_IsZero demonstrates checking for zero/empty IDs
func ExampleID_IsZero() {
	var emptyID types.ID
	validID := types.NewID()

	fmt.Println("Empty ID is zero:", emptyID.IsZero())
	fmt.Println("Valid ID is zero:", validID.IsZero())
	// Output:
	// Empty ID is zero: true
	// Valid ID is zero: false
}

// ExampleID_MarshalJSON demonstrates JSON serialization
func ExampleID_MarshalJSON() {
	type User struct {
		ID   types.ID `json:"id"`
		Name string   `json:"name"`
	}

	user := User{
		ID:   types.NewID(),
		Name: "Alice",
	}

	data, err := json.Marshal(user)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("JSON contains ID field:", len(data) > 0)
	// Output: JSON contains ID field: true
}

// ExampleID_UnmarshalJSON demonstrates JSON deserialization
func ExampleID_UnmarshalJSON() {
	type User struct {
		ID   types.ID `json:"id"`
		Name string   `json:"name"`
	}

	jsonData := `{"id":"550e8400-e29b-41d4-a716-446655440000","name":"Alice"}`

	var user User
	if err := json.Unmarshal([]byte(jsonData), &user); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("User ID:", user.ID.String())
	fmt.Println("User Name:", user.Name)
	// Output:
	// User ID: 550e8400-e29b-41d4-a716-446655440000
	// User Name: Alice
}
