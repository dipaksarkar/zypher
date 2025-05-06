#!/bin/bash
# Zypher Test Runner Script
# This script automates the process of testing the Zypher encoder/decoder system

# Colors for terminal output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}        ZYPHER TEST RUNNER SCRIPT        ${NC}"
echo -e "${BLUE}==========================================${NC}"

# Check if proper directories exist
if [ ! -d "../encoder" ] || [ ! -d "../loader" ]; then
    echo -e "${RED}Error: Cannot find encoder or loader directories${NC}"
    exit 1
fi

# Set paths
ZYPHER_ROOT=$(cd .. && pwd)
ZYPHER_BIN="$ZYPHER_ROOT/zypher"
ZYPHER_LOADER="$ZYPHER_ROOT/loader/zypher.so"

# Check if encoder binary exists
if [ ! -f "$ZYPHER_BIN" ]; then
    echo -e "${BLUE}Zypher encoder binary not found. Building...${NC}"
    cd "$ZYPHER_ROOT" && make encoder
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build encoder binary${NC}"
        exit 1
    fi
fi

# Check if loader extension exists
if [ ! -f "$ZYPHER_LOADER" ]; then
    echo -e "${BLUE}Zypher loader extension not found. Building...${NC}"
    cd "$ZYPHER_ROOT" && make loader
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build loader extension${NC}"
        exit 1
    fi
fi

# Test function
run_test() {
    local test_file=$1
    local test_name=$(basename "$test_file" .php)
    local encoded_file="$test_name.encoded.php"
    
    echo -e "\n${BLUE}Testing: $test_name${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    
    # Run original PHP file
    echo -e "${BLUE}Running original PHP file:${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    php "$test_file" > "$test_name.original.out"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Original PHP execution failed${NC}"
        cat "$test_name.original.out"
        return 1
    fi
    
    # Encode the PHP file
    echo -e "\n${BLUE}Encoding PHP file:${NC}"
    "$ZYPHER_BIN" -o "$encoded_file" "$test_file"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Encoding failed${NC}"
        return 1
    fi
    
    # Run encoded file with loader
    echo -e "\n${BLUE}Running encoded file with Zypher loader:${NC}"
    echo -e "${BLUE}----------------------------------------${NC}"
    php -d extension="$ZYPHER_LOADER" "$encoded_file" > "$test_name.encoded.out"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Encoded PHP execution failed${NC}"
        cat "$test_name.encoded.out"
        return 1
    fi
    
    # Compare outputs
    echo -e "\n${BLUE}Comparing outputs:${NC}"
    diff "$test_name.original.out" "$test_name.encoded.out" > /dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Test passed: Original and encoded outputs match${NC}"
        return 0
    else
        echo -e "${RED}✗ Test failed: Outputs do not match${NC}"
        echo -e "${BLUE}Differences:${NC}"
        diff "$test_name.original.out" "$test_name.encoded.out"
        return 1
    fi
}

# Run all tests or specific tests if provided
if [ $# -eq 0 ]; then
    # Run all tests
    echo -e "${BLUE}Running all tests in tests directory...${NC}"
    
    # Count successful and failed tests
    success_count=0
    fail_count=0
    
    # Run basic test
    if [ -f "basic.php" ]; then
        run_test "basic.php"
        if [ $? -eq 0 ]; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi
    
    # Run advanced test
    if [ -f "advanced.php" ]; then
        run_test "advanced.php"
        if [ $? -eq 0 ]; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    fi
    
    # Run any additional .php files
    for test_file in $(ls *.php | grep -v "basic.php" | grep -v "advanced.php" | grep -v "encoded.php"); do
        run_test "$test_file"
        if [ $? -eq 0 ]; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    # Print summary
    echo -e "\n${BLUE}==========================================${NC}"
    echo -e "${BLUE}              TEST SUMMARY              ${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${GREEN}Passed: $success_count${NC}"
    echo -e "${RED}Failed: $fail_count${NC}"
    echo -e "${BLUE}Total:  $((success_count + fail_count))${NC}"
    
    # Set exit code based on test results
    if [ $fail_count -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed successfully!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed.${NC}"
        exit 1
    fi
else
    # Run specific test(s)
    for test_file in "$@"; do
        if [ -f "$test_file" ]; then
            run_test "$test_file"
        else
            echo -e "${RED}Test file not found: $test_file${NC}"
        fi
    done
fi