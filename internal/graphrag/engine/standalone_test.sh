#!/bin/bash
# Standalone test script that tests template.go in isolation

set -e

echo "Running standalone template engine tests..."

# Run tests with only the template files
go test -v \
    github.com/zeroroot-ai/gibson/internal/graphrag/engine/template_test.go \
    github.com/zeroroot-ai/gibson/internal/graphrag/engine/template.go

echo ""
echo "Running benchmarks..."

# Run benchmarks
go test -bench=. -benchmem \
    github.com/zeroroot-ai/gibson/internal/graphrag/engine/template_test.go \
    github.com/zeroroot-ai/gibson/internal/graphrag/engine/template.go

echo ""
echo "All tests passed!"
