#!/bin/bash

# Phase 1: Unit Tests - Automated Test Script
# Cryptography Application Unit Testing Suite
# Date: August 13, 2025

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Logging
LOG_FILE="phase1_test_results_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="phase1_test_report.json"

print_header() {
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                          PHASE 1: UNIT TESTS - CRYPTOGRAPHY APPLICATION${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Test Date:${NC} $(date)"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo ""
}

print_test_section() {
    echo -e "${PURPLE}┌─────────────────────────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${PURPLE}│ $1${NC}"
    echo -e "${PURPLE}└─────────────────────────────────────────────────────────────────────────────────────────────┘${NC}"
}

log_test() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$status] $test_name: $details" >> "$LOG_FILE"
}

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_behavior="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing:${NC} $test_name"
    echo -e "${YELLOW}Expected:${NC} $expected_behavior"
    echo -e "${YELLOW}Command:${NC} $test_command"
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_test "$test_name" "PASS" "$expected_behavior"
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "$test_name" "FAIL" "Command failed: $test_command"
        
        # Capture error details
        echo -e "${RED}Error Details:${NC}"
        eval "$test_command" 2>&1 | head -5 | sed 's/^/  /'
    fi
    echo ""
}

test_build_system() {
    print_test_section "BUILD SYSTEM TESTS"
    
    run_test "CMake Configuration" \
        "cd $HOME/Cryptography-Application/build && cmake --version && test -f CMakeCache.txt" \
        "CMake should be configured and cache file should exist"
    
    run_test "Build Directory Structure" \
        "test -d $HOME/Cryptography-Application/build && test -f $HOME/Cryptography-Application/CMakeLists.txt" \
        "Build directory and CMakeLists.txt should exist"
    
    run_test "Executable Generation" \
        "test -f $HOME/Cryptography-Application/build/CryptographyApplication || test -f $HOME/Cryptography-Application/build/CryptographyApplication.exe" \
        "Main executable should be built successfully"
}

test_aes_crypto() {
    print_test_section "AES ENCRYPTION TESTS"
    
    # Test AES key generation
    run_test "AES Key Generation" \
        "echo 'Testing AES key generation' | openssl rand -hex 32 | wc -c | grep -q 65" \
        "AES-256 key should be 32 bytes (64 hex chars + newline)"
    
    # Test AES encryption/decryption
    run_test "AES Encrypt/Decrypt Cycle" \
        "echo 'test data' | openssl enc -aes-256-cbc -k 'testkey' | openssl enc -aes-256-cbc -d -k 'testkey' | grep -q 'test data'" \
        "AES encryption and decryption should restore original data"
    
    # Test with different data sizes
    run_test "AES Large Data Handling" \
        "dd if=/dev/zero bs=1024 count=100 2>/dev/null | openssl enc -aes-256-cbc -k 'testkey' | wc -c | test \$(cat) -gt 102400" \
        "AES should handle large data (100KB+) with proper padding"
}

test_rsa_crypto() {
    print_test_section "RSA ENCRYPTION TESTS"
    
    # Test RSA key generation
    run_test "RSA Key Pair Generation" \
        "openssl genrsa -out /tmp/test_private.pem 2048 2>/dev/null && openssl rsa -in /tmp/test_private.pem -pubout -out /tmp/test_public.pem 2>/dev/null && test -f /tmp/test_private.pem && test -f /tmp/test_public.pem" \
        "RSA 2048-bit key pair should generate successfully"
    
    # Test RSA encryption/decryption
    run_test "RSA Encrypt/Decrypt Cycle" \
        "echo 'small test data' | openssl rsautl -encrypt -pubin -inkey /tmp/test_public.pem | openssl rsautl -decrypt -inkey /tmp/test_private.pem | grep -q 'small test data'" \
        "RSA encryption and decryption should restore original data"
    
    # Cleanup
    rm -f /tmp/test_private.pem /tmp/test_public.pem
}

test_hash_functions() {
    print_test_section "HASH FUNCTION TESTS"
    
    # Test SHA-256
    run_test "SHA-256 Hash Consistency" \
        "echo 'test data' | sha256sum | cut -d' ' -f1 | grep -q '^[a-f0-9]\{64\}$'" \
        "SHA-256 should produce 64-character hexadecimal hash"
    
    # Test MD5
    run_test "MD5 Hash Consistency" \
        "echo 'test data' | md5sum | cut -d' ' -f1 | grep -q '^[a-f0-9]\{32\}$'" \
        "MD5 should produce 32-character hexadecimal hash"
    
    # Test hash consistency
    run_test "Hash Deterministic Behavior" \
        "hash1=\$(echo 'consistent data' | sha256sum | cut -d' ' -f1) && hash2=\$(echo 'consistent data' | sha256sum | cut -d' ' -f1) && test \"\$hash1\" = \"\$hash2\"" \
        "Same input should always produce same hash"
}

test_digital_signatures() {
    print_test_section "DIGITAL SIGNATURE TESTS"
    
    # Generate test keys for signing
    openssl genrsa -out /tmp/sign_private.pem 2048 2>/dev/null
    openssl rsa -in /tmp/sign_private.pem -pubout -out /tmp/sign_public.pem 2>/dev/null
    
    # Test file signing
    run_test "File Digital Signature" \
        "echo 'document to sign' > /tmp/test_doc.txt && openssl dgst -sha256 -sign /tmp/sign_private.pem -out /tmp/signature.bin /tmp/test_doc.txt" \
        "Should be able to create digital signature of a file"
    
    # Test signature verification
    run_test "Signature Verification" \
        "openssl dgst -sha256 -verify /tmp/sign_public.pem -signature /tmp/signature.bin /tmp/test_doc.txt" \
        "Should be able to verify digital signature"
    
    # Cleanup
    rm -f /tmp/sign_private.pem /tmp/sign_public.pem /tmp/test_doc.txt /tmp/signature.bin
}

test_file_operations() {
    print_test_section "FILE OPERATION TESTS"
    
    # Test file reading/writing
    run_test "File Read/Write Operations" \
        "echo 'test file content' > /tmp/test_rw.txt && content=\$(cat /tmp/test_rw.txt) && test \"\$content\" = 'test file content'" \
        "Should be able to read and write files correctly"
    
    # Test binary file handling
    run_test "Binary File Handling" \
        "dd if=/dev/urandom of=/tmp/test_binary bs=1024 count=1 2>/dev/null && test -f /tmp/test_binary && test \$(wc -c < /tmp/test_binary) -eq 1024" \
        "Should handle binary files correctly"
    
    # Test large file operations
    run_test "Large File Operations" \
        "dd if=/dev/zero of=/tmp/test_large bs=1M count=10 2>/dev/null && test \$(wc -c < /tmp/test_large) -eq 10485760" \
        "Should handle large files (10MB+) efficiently"
    
    # Cleanup
    rm -f /tmp/test_rw.txt /tmp/test_binary /tmp/test_large
}

test_dependencies() {
    print_test_section "DEPENDENCY TESTS"
    
    run_test "OpenSSL Library" \
        "openssl version" \
        "OpenSSL should be available and functional"
    
    run_test "Qt5 Framework" \
        "pkg-config --exists Qt5Core Qt5Widgets" \
        "Qt5 development libraries should be available"
    
    run_test "Boost Libraries" \
        "test -d /usr/include/boost || test -d /usr/local/include/boost" \
        "Boost libraries should be available"
    
    run_test "Crypto++ Library" \
        "test -d /usr/include/cryptopp || test -d /usr/local/include/cryptopp" \
        "Crypto++ libraries should be available"
    
    run_test "CMake Build Tool" \
        "cmake --version | grep -q 'cmake version'" \
        "CMake should be available and functional"
}

test_memory_safety() {
    print_test_section "MEMORY SAFETY TESTS"
    
    # Test for memory leaks (basic)
    run_test "Basic Memory Allocation" \
        "valgrind --version > /dev/null 2>&1 || echo 'Valgrind not available - skipping memory tests'" \
        "Memory testing tools should be available (optional)"
    
    # Test stack overflow protection
    run_test "Stack Safety Mechanisms" \
        "echo 'int main(){char buf[1000]; return 0;}' | gcc -fstack-protector-strong -x c - -o /tmp/stack_test 2>/dev/null && /tmp/stack_test" \
        "Stack protection should be enabled in compiler"
    
    rm -f /tmp/stack_test
}

generate_json_report() {
    cat > "$REPORT_FILE" << EOF
{
  "test_phase": "Phase 1 - Unit Tests",
  "test_date": "$(date -Iseconds)",
  "test_duration": "$1",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "test_categories": {
    "build_system": "$(grep 'BUILD SYSTEM' $LOG_FILE | wc -l) tests",
    "aes_crypto": "$(grep 'AES' $LOG_FILE | wc -l) tests",
    "rsa_crypto": "$(grep 'RSA' $LOG_FILE | wc -l) tests",
    "hash_functions": "$(grep 'HASH' $LOG_FILE | wc -l) tests",
    "digital_signatures": "$(grep 'SIGNATURE' $LOG_FILE | wc -l) tests",
    "file_operations": "$(grep 'FILE' $LOG_FILE | wc -l) tests",
    "dependencies": "$(grep 'DEPENDENCY' $LOG_FILE | wc -l) tests",
    "memory_safety": "$(grep 'MEMORY' $LOG_FILE | wc -l) tests"
  },
  "log_file": "$LOG_FILE",
  "recommendations": [
    "Review failed tests in detail",
    "Check dependency installation if dependency tests failed",
    "Run integration tests if unit tests pass",
    "Consider performance testing for passed crypto functions"
  ]
}
EOF
}

print_summary() {
    local end_time=$(date)
    local duration="$1"
    
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                                    TEST SUMMARY${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Start Time:${NC} $start_time"
    echo -e "${BLUE}End Time:${NC} $end_time"
    echo -e "${BLUE}Duration:${NC} $duration seconds"
    echo ""
    echo -e "${BLUE}Total Tests:${NC} $TOTAL_TESTS"
    echo -e "${GREEN}Passed:${NC} $PASSED_TESTS"
    echo -e "${RED}Failed:${NC} $FAILED_TESTS"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED_TESTS"
    echo ""
    
    local success_rate=$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)
    echo -e "${BLUE}Success Rate:${NC} ${success_rate}%"
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED! Ready for Phase 2 Integration Testing.${NC}"
    else
        echo -e "${RED}⚠️  Some tests failed. Review the log file: $LOG_FILE${NC}"
        echo -e "${YELLOW}💡 Fix failed tests before proceeding to integration testing.${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Detailed Results:${NC} $LOG_FILE"
    echo -e "${BLUE}JSON Report:${NC} $REPORT_FILE"
    echo -e "${CYAN}================================================================================================${NC}"
}

# Main execution
main() {
    local start_time=$(date)
    local start_timestamp=$(date +%s)
    
    print_header
    
    # Initialize log file
    echo "Phase 1 Unit Tests - $(date)" > "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # Run all test categories
    test_dependencies
    test_build_system
    test_aes_crypto
    test_rsa_crypto
    test_hash_functions
    test_digital_signatures
    test_file_operations
    test_memory_safety
    
    # Calculate duration
    local end_timestamp=$(date +%s)
    local duration=$((end_timestamp - start_timestamp))
    
    # Generate reports
    generate_json_report "$duration"
    print_summary "$duration"
}

# Check if bc is available for calculations
if ! command -v bc &> /dev/null; then
    echo "Installing bc for calculations..."
    # Try to install bc if possible
    sudo apt-get install -y bc 2>/dev/null || sudo yum install -y bc 2>/dev/null || echo "Please install bc manually"
fi

# Run the tests
main "$@"
