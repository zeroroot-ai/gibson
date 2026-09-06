#!/bin/bash
# Check coverage meets threshold

COVERAGE_FILE=$1
THRESHOLD=$2

# Get total coverage percentage
COVERAGE=$(go tool cover -func=$COVERAGE_FILE | grep total | awk '{print $3}' | sed 's/%//')

# Compare with threshold using bc for floating point
RESULT=$(echo "$COVERAGE >= $THRESHOLD" | bc -l)

if [ "$RESULT" -eq 1 ]; then
    echo "✓ Coverage $COVERAGE% meets threshold $THRESHOLD%"
    exit 0
else
    echo "✗ Coverage $COVERAGE% is below threshold $THRESHOLD%"
    exit 1
fi
