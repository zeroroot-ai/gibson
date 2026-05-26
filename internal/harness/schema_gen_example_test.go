package harness_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/harness"
)

// Example demonstrates basic schema generation from a simple struct
func ExampleSchemaFromType_simple() {
	type Person struct {
		Name  string `json:"name"`
		Age   int    `json:"age"`
		Email string `json:"email,omitempty"`
	}

	schema := harness.SchemaFromType[Person]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "age": {
	//       "type": "integer"
	//     },
	//     "email": {
	//       "type": "string"
	//     },
	//     "name": {
	//       "type": "string"
	//     }
	//   },
	//   "required": [
	//     "name",
	//     "age"
	//   ]
	// }
}

// Example demonstrates schema generation with nested structs
func ExampleSchemaFromType_nested() {
	type Address struct {
		Street  string `json:"street"`
		City    string `json:"city"`
		ZipCode string `json:"zip_code,omitempty"`
	}

	type User struct {
		Name    string  `json:"name"`
		Address Address `json:"address"`
	}

	schema := harness.SchemaFromType[User]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "address": {
	//       "type": "object",
	//       "properties": {
	//         "city": {
	//           "type": "string"
	//         },
	//         "street": {
	//           "type": "string"
	//         },
	//         "zip_code": {
	//           "type": "string"
	//         }
	//       },
	//       "required": [
	//         "street",
	//         "city"
	//       ]
	//     },
	//     "name": {
	//       "type": "string"
	//     }
	//   },
	//   "required": [
	//     "name",
	//     "address"
	//   ]
	// }
}

// Example demonstrates schema generation with arrays
func ExampleSchemaFromType_arrays() {
	type Project struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}

	schema := harness.SchemaFromType[Project]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "name": {
	//       "type": "string"
	//     },
	//     "tags": {
	//       "type": "array",
	//       "items": {
	//         "type": "string"
	//       }
	//     }
	//   },
	//   "required": [
	//     "name",
	//     "tags"
	//   ]
	// }
}

// Example demonstrates schema generation with time.Time fields
func ExampleSchemaFromType_timeFields() {
	type Event struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
	}

	schema := harness.SchemaFromType[Event]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "created_at": {
	//       "type": "string",
	//       "format": "date-time"
	//     },
	//     "name": {
	//       "type": "string"
	//     }
	//   },
	//   "required": [
	//     "name",
	//     "created_at"
	//   ]
	// }
}

// Example demonstrates TypeName function
func ExampleTypeName() {
	type CustomStruct struct {
		Field string
	}

	fmt.Println(harness.TypeName[CustomStruct]())
	fmt.Println(harness.TypeName[string]())
	fmt.Println(harness.TypeName[int]())

	// Output:
	// CustomStruct
	// string
	// int
}

// Example demonstrates schema generation with embedded fields
func ExampleSchemaFromType_embedded() {
	type Timestamps struct {
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	type Article struct {
		Timestamps
		Title   string `json:"title"`
		Content string `json:"content"`
	}

	schema := harness.SchemaFromType[Article]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "content": {
	//       "type": "string"
	//     },
	//     "created_at": {
	//       "type": "string",
	//       "format": "date-time"
	//     },
	//     "title": {
	//       "type": "string"
	//     },
	//     "updated_at": {
	//       "type": "string",
	//       "format": "date-time"
	//     }
	//   },
	//   "required": [
	//     "created_at",
	//     "updated_at",
	//     "title",
	//     "content"
	//   ]
	// }
}

// Example demonstrates schema generation with pointer fields (optional)
func ExampleSchemaFromType_pointers() {
	type OptionalFields struct {
		Required string  `json:"required"`
		Optional *string `json:"optional,omitempty"`
	}

	schema := harness.SchemaFromType[OptionalFields]()
	jsonBytes, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Println(string(jsonBytes))

	// Output:
	// {
	//   "type": "object",
	//   "properties": {
	//     "optional": {
	//       "type": "string"
	//     },
	//     "required": {
	//       "type": "string"
	//     }
	//   },
	//   "required": [
	//     "required"
	//   ]
	// }
}
