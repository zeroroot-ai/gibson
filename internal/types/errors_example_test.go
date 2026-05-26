package types_test

import (
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Example demonstrates basic error creation and handling
func Example_basicError() {
	err := types.NewError(types.CONFIG_LOAD_FAILED, "failed to load configuration file")
	fmt.Println(err.Error())
	// Output: [CONFIG_LOAD_FAILED] failed to load configuration file
}

// Example demonstrates wrapping errors to preserve context
func Example_wrappedError() {
	originalErr := errors.New("file not found")
	err := types.WrapError(types.CONFIG_NOT_FOUND, "configuration missing", originalErr)
	fmt.Println(err.Error())
	// Output: [CONFIG_NOT_FOUND] configuration missing: file not found
}

// Example demonstrates creating retryable errors for transient failures
func Example_retryableError() {
	err := types.NewRetryableError(types.TARGET_CONNECTION_FAILED, "connection timeout")
	fmt.Printf("Error: %s\nRetryable: %v\n", err.Error(), err.Retryable)
	// Output:
	// Error: [TARGET_CONNECTION_FAILED] connection timeout
	// Retryable: true
}

// Example demonstrates error matching with errors.Is()
func Example_errorMatching() {
	err1 := types.NewError(types.DB_CONNECTION_LOST, "database disconnected")
	err2 := types.NewError(types.DB_CONNECTION_LOST, "different message")
	err3 := types.NewError(types.DB_QUERY_FAILED, "query failed")

	// Same error code matches
	fmt.Printf("err1 matches err2: %v\n", errors.Is(err1, err2))
	// Different error code doesn't match
	fmt.Printf("err1 matches err3: %v\n", errors.Is(err1, err3))
	// Output:
	// err1 matches err2: true
	// err1 matches err3: false
}

// Example demonstrates error unwrapping to access the original cause
func Example_errorUnwrapping() {
	originalErr := errors.New("disk full")
	wrappedErr := types.WrapError(types.DB_OPEN_FAILED, "cannot open database", originalErr)

	// Access the wrapped error using errors.Is()
	if errors.Is(wrappedErr, originalErr) {
		fmt.Println("Found original error in chain")
	}

	// Access the cause directly
	if unwrapped := errors.Unwrap(wrappedErr); unwrapped != nil {
		fmt.Printf("Cause: %v\n", unwrapped)
	}
	// Output:
	// Found original error in chain
	// Cause: disk full
}

// Example demonstrates using errors.As() to extract GibsonError
func Example_errorExtraction() {
	err := types.WrapError(types.CRYPTO_KEY_NOT_FOUND, "encryption key missing", errors.New("vault error"))

	var gibsonErr *types.GibsonError
	if errors.As(err, &gibsonErr) {
		fmt.Printf("Code: %s\n", gibsonErr.Code)
		fmt.Printf("Message: %s\n", gibsonErr.Message)
		fmt.Printf("Retryable: %v\n", gibsonErr.Retryable)
	}
	// Output:
	// Code: CRYPTO_KEY_NOT_FOUND
	// Message: encryption key missing
	// Retryable: false
}

// Example demonstrates handling errors with different codes
func Example_errorHandling() {
	handleError := func(err error) {
		var gibsonErr *types.GibsonError
		if !errors.As(err, &gibsonErr) {
			fmt.Println("Not a Gibson error")
			return
		}

		switch gibsonErr.Code {
		case types.DB_CONNECTION_LOST:
			fmt.Println("Attempting to reconnect to database...")
		case types.TARGET_CONNECTION_FAILED:
			if gibsonErr.Retryable {
				fmt.Println("Retrying connection...")
			}
		case types.CREDENTIAL_EXPIRED:
			fmt.Println("Refreshing credentials...")
		default:
			fmt.Printf("Unhandled error: %s\n", gibsonErr.Code)
		}
	}

	// Test different error types
	handleError(types.NewError(types.DB_CONNECTION_LOST, "connection lost"))
	handleError(types.NewRetryableError(types.TARGET_CONNECTION_FAILED, "timeout"))
	handleError(types.NewError(types.CREDENTIAL_EXPIRED, "token expired"))
	// Output:
	// Attempting to reconnect to database...
	// Retrying connection...
	// Refreshing credentials...
}
