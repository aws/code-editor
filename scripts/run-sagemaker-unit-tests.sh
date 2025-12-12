#!/bin/bash

set -e

echo "INFO: Running SageMaker Code Editor Unit Tests"

# Get project root
PROJ_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$PROJ_ROOT"

# Check if code-editor-src exists, if not prepare it
if [ ! -d "code-editor-src" ]; then
    echo "INFO: code-editor-src not found, preparing source..."
    ./scripts/prepare-src.sh code-editor-sagemaker-server
fi

# Check if Node.js and npx are available
if ! command -v node &> /dev/null || ! command -v npx &> /dev/null; then
    echo "ERROR: Node.js and npm are required to run tests"
    exit 1
fi

#Install required dependencies
echo "Installing dependencies..."
npm install -g typescript
npm install --save-dev @types/node

# Compile and run each test file
TEST_DIR="sagemaker-tests"
FAILED_TESTS=0
TOTAL_TESTS=0

# First compile all TypeScript files
echo "Compiling TypeScript files..."
if ! npx tsc --project "$TEST_DIR/tsconfig.json" --outDir /tmp/tests; then
    echo "ERROR: TypeScript compilation failed"
    exit 1
fi

for test_file in "$TEST_DIR"/*.test.ts; do
    if [ -f "$test_file" ]; then
        TOTAL_TESTS=$((TOTAL_TESTS + 1))
        test_name=$(basename "$test_file" .test.ts)
        
        echo "Running $test_name tests..."
        
        # Run the compiled JavaScript
        if node "/tmp/tests/$(basename "$test_file" .ts).js"; then
            echo "SUCCESS: $test_name tests passed"
        else
            echo "FAILED: $test_name tests failed"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
        echo ""
    fi
done

# Summary
echo "INFO: Test Summary:"
echo "Total test suites: $TOTAL_TESTS"
echo "Failed test suites: $FAILED_TESTS"
echo "Passed test suites: $((TOTAL_TESTS - FAILED_TESTS))"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "SUCCESS: All tests passed!"
    exit 0
else
    echo "FAILED: $FAILED_TESTS test suite(s) failed"
    exit 1
fi
