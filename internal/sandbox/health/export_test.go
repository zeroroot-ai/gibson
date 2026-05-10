package health

// ResetForTest exposes resetForTest to package-external unit tests.
//
// Spec setec-sandbox-prod-default Task 55: production callers MUST NOT
// use this — it would let a bug cause the gauge to flap. The
// test-only export pattern keeps the production API safe while
// permitting isolated test cases.
var ResetForTest = resetForTest
