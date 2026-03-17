package state

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// JSONSet sets a JSON document or value at the specified path within a key.
// This wraps the JSON.SET command from RedisJSON.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - key: Redis key to store the JSON document
//   - path: JSON path (use "$" or "." for root)
//   - value: Any Go value that can be marshaled to JSON
//
// Returns an error if the operation fails or if JSON marshaling fails.
//
// Example:
//
//	type User struct {
//	    Name string `json:"name"`
//	    Age  int    `json:"age"`
//	}
//
//	user := User{Name: "Alice", Age: 30}
//	err := client.JSONSet(ctx, "user:1", "$", user)
func (c *StateClient) JSONSet(ctx context.Context, key, path string, value any) error {
	// Marshal value to JSON
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("json marshal failed: %w", err)
	}

	// Execute JSON.SET command
	result := c.client.Do(ctx, "JSON.SET", key, path, string(data))
	if err := result.Err(); err != nil {
		return fmt.Errorf("JSON.SET failed for key %q: %w", key, err)
	}

	return nil
}

// JSONGet retrieves a JSON document or value at the specified path and unmarshals it into dest.
// This wraps the JSON.GET command from RedisJSON.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - key: Redis key containing the JSON document
//   - path: JSON path (use "$" or "." for root)
//   - dest: Pointer to a variable where the result will be unmarshaled
//
// Returns ErrNotFound if the key does not exist.
// Returns an error if the operation fails or if JSON unmarshaling fails.
//
// Note: When using JSONPath syntax (paths starting with "$"), RedisJSON returns
// results as an array even for single values. This function automatically unwraps
// single-element arrays when the destination is not a slice/array type.
//
// Example:
//
//	var user User
//	err := client.JSONGet(ctx, "user:1", "$", &user)
//	if state.IsNotFound(err) {
//	    // Handle missing key
//	}
func (c *StateClient) JSONGet(ctx context.Context, key, path string, dest any) error {
	// Execute JSON.GET command
	result := c.client.Do(ctx, "JSON.GET", key, path)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return ErrNotFound
		}
		return fmt.Errorf("JSON.GET failed for key %q: %w", key, err)
	}

	// Get the raw JSON string
	data, err := result.Text()
	if err != nil {
		return fmt.Errorf("failed to read JSON.GET result: %w", err)
	}

	// RedisJSON with JSONPath ($) returns results as an array, even for single values.
	// If the path starts with "$" and the result is an array with exactly one element,
	// and the destination is not expecting a slice, unwrap the array.
	if len(path) > 0 && path[0] == '$' {
		// Check if result is a JSON array
		trimmed := []byte(data)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			// Parse as generic array first
			var arr []json.RawMessage
			if err := json.Unmarshal(trimmed, &arr); err == nil && len(arr) == 1 {
				// Single element array - unwrap it for non-slice destinations
				data = string(arr[0])
			}
		}
	}

	// Unmarshal into dest
	if err := json.Unmarshal([]byte(data), dest); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	return nil
}

// JSONDel deletes a JSON document or value at the specified path.
// This wraps the JSON.DEL command from RedisJSON.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - key: Redis key containing the JSON document
//   - path: JSON path (use "$" or "." for root to delete entire document)
//
// Returns the number of paths deleted (0 if path doesn't exist).
// Returns an error if the operation fails.
//
// Example:
//
//	// Delete entire document
//	err := client.JSONDel(ctx, "user:1", "$")
//
//	// Delete specific field
//	err := client.JSONDel(ctx, "user:1", "$.metadata")
func (c *StateClient) JSONDel(ctx context.Context, key, path string) error {
	// Execute JSON.DEL command
	result := c.client.Do(ctx, "JSON.DEL", key, path)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return nil // Key doesn't exist, not an error
		}
		return fmt.Errorf("JSON.DEL failed for key %q: %w", key, err)
	}

	return nil
}

// JSONMGet retrieves JSON values from multiple keys at the specified path.
// This wraps the JSON.MGET command from RedisJSON.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - keys: List of Redis keys to fetch
//   - path: JSON path to retrieve from each key
//
// Returns a slice of json.RawMessage, one per key. Nil entries indicate the key doesn't exist.
// Returns an error if the operation fails.
//
// Example:
//
//	keys := []string{"user:1", "user:2", "user:3"}
//	results, err := client.JSONMGet(ctx, keys, "$")
//	for i, raw := range results {
//	    if raw == nil {
//	        fmt.Printf("Key %s not found\n", keys[i])
//	        continue
//	    }
//	    var user User
//	    json.Unmarshal(raw, &user)
//	}
func (c *StateClient) JSONMGet(ctx context.Context, keys []string, path string) ([]json.RawMessage, error) {
	if len(keys) == 0 {
		return []json.RawMessage{}, nil
	}

	// Build command arguments: JSON.MGET key1 key2 ... keyN path
	args := make([]interface{}, 0, len(keys)+2)
	args = append(args, "JSON.MGET")
	for _, key := range keys {
		args = append(args, key)
	}
	args = append(args, path)

	// Execute JSON.MGET command
	result := c.client.Do(ctx, args...)
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("JSON.MGET failed: %w", err)
	}

	// Parse result as array of strings
	vals, err := result.Slice()
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON.MGET result: %w", err)
	}

	// Convert to json.RawMessage slice
	results := make([]json.RawMessage, len(vals))
	for i, val := range vals {
		if val == nil {
			results[i] = nil
			continue
		}

		// Convert interface{} to string
		str, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type in JSON.MGET result at index %d", i)
		}
		results[i] = json.RawMessage(str)
	}

	return results, nil
}

// JSONNumIncrBy atomically increments a numeric value in a JSON document.
// This wraps the JSON.NUMINCRBY command from RedisJSON.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - key: Redis key containing the JSON document
//   - path: JSON path to the numeric field
//   - amount: Amount to increment (can be negative to decrement)
//
// Returns the new value after increment.
// Returns an error if the operation fails or if the field is not numeric.
//
// Example:
//
//	// Increment view count
//	newCount, err := client.JSONNumIncrBy(ctx, "article:123", "$.views", 1)
//
//	// Decrement stock quantity
//	newQty, err := client.JSONNumIncrBy(ctx, "product:456", "$.quantity", -1)
func (c *StateClient) JSONNumIncrBy(ctx context.Context, key, path string, amount float64) (float64, error) {
	// Execute JSON.NUMINCRBY command
	result := c.client.Do(ctx, "JSON.NUMINCRBY", key, path, amount)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("JSON.NUMINCRBY failed for key %q: %w", key, err)
	}

	// Parse result as string (RedisJSON returns stringified number)
	strVal, err := result.Text()
	if err != nil {
		return 0, fmt.Errorf("failed to read JSON.NUMINCRBY result: %w", err)
	}

	// Parse string as float64
	var newValue float64
	if err := json.Unmarshal([]byte(strVal), &newValue); err != nil {
		return 0, fmt.Errorf("failed to parse numeric result: %w", err)
	}

	return newValue, nil
}
