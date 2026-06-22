package health

// ResetForTest is the in-package test helper exported for the
// tier_gauge_test.go file to use across-package. The underlying
// resetForTest is unexported in tier_gauge.go.
var ResetForTest = resetForTest
