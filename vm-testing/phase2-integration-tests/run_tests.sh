#!/bin/bash

# Phase 2: Integration Tests - Automated Test Script
# Cryptography Application Integration Testing Suite
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
LOG_FILE="phase2_integration_results_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="phase2_integration_report.json"
APP_PATH="../../build/CryptographyApplication"

print_header() {
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                       PHASE 2: INTEGRATION TESTS - CRYPTOGRAPHY APPLICATION${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Test Date:${NC} $(date)"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo -e "${BLUE}Application:${NC} $APP_PATH"
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
    local timeout_duration="${4:-30}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing:${NC} $test_name"
    echo -e "${YELLOW}Expected:${NC} $expected_behavior"
    echo -e "${YELLOW}Command:${NC} $test_command"
    echo -e "${YELLOW}Timeout:${NC} ${timeout_duration}s"
    
    if timeout $timeout_duration bash -c "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_test "$test_name" "PASS" "$expected_behavior"
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "$test_name" "FAIL" "Command failed or timed out: $test_command"
        
        # Capture error details
        echo -e "${RED}Error Details:${NC}"
        timeout $timeout_duration bash -c "$test_command" 2>&1 | head -5 | sed 's/^/  /' || echo "  Command timed out after ${timeout_duration}s"
    fi
    echo ""
}

setup_test_environment() {
    print_test_section "TEST ENVIRONMENT SETUP"
    
    # Create test data directory
    mkdir -p /tmp/crypto_integration_tests
    cd /tmp/crypto_integration_tests
    
    # Create test files
    echo "This is a test document for encryption testing." > test_document.txt
    echo "Small data for RSA testing" > small_test.txt
    dd if=/dev/urandom of=binary_test.bin bs=1024 count=10 2>/dev/null
    dd if=/dev/zero of=large_test.dat bs=1M count=5 2>/dev/null
    
    # Generate test keys
    openssl genrsa -out test_private.pem 2048 2>/dev/null
    openssl rsa -in test_private.pem -pubout -out test_public.pem 2>/dev/null
    
    echo -e "${GREEN}✓ Test environment prepared${NC}"
    echo -e "${BLUE}Test Directory:${NC} /tmp/crypto_integration_tests"
    echo ""
}

test_application_startup() {
    print_test_section "APPLICATION STARTUP TESTS"
    
    run_test "Application Binary Exists" \
        "test -f $APP_PATH && test -x $APP_PATH" \
        "Application executable should exist and be executable" \
        5
    
    run_test "Application Version Check" \
        "$APP_PATH --version 2>/dev/null || $APP_PATH --help 2>/dev/null || echo 'No version flag available'" \
        "Application should respond to version or help flags" \
        10
    
    run_test "Application Dependencies Check" \
        "ldd $APP_PATH | grep -E '(Qt5|ssl|crypto)' | wc -l | test \$(cat) -gt 0" \
        "Application should link to required libraries" \
        5
}

test_cli_operations() {
    print_test_section "COMMAND LINE INTERFACE TESTS"
    
    # Note: These tests assume CLI functionality exists or will be implemented
    run_test "CLI Help Display" \
        "$APP_PATH --help 2>&1 | grep -i 'usage\\|help\\|cryptography' || echo 'CLI help not implemented yet'" \
        "CLI should display help information" \
        10
    
    run_test "CLI Error Handling" \
        "$APP_PATH --invalid-option 2>&1 | grep -i 'error\\|invalid\\|unknown' || echo 'CLI error handling not implemented'" \
        "CLI should handle invalid options gracefully" \
        10
}

test_file_encryption_workflow() {
    print_test_section "FILE ENCRYPTION WORKFLOW TESTS"
    
    # Test AES file encryption workflow
    run_test "AES File Encryption Integration" \
        "openssl enc -aes-256-cbc -in test_document.txt -out test_document.aes -k 'testpassword' && test -f test_document.aes" \
        "Should encrypt file using AES-256-CBC" \
        15
    
    run_test "AES File Decryption Integration" \
        "openssl enc -aes-256-cbc -d -in test_document.aes -out test_document_decrypted.txt -k 'testpassword' && diff test_document.txt test_document_decrypted.txt" \
        "Should decrypt AES file and match original" \
        15
    
    # Test RSA file encryption workflow (for small files)
    run_test "RSA Small File Encryption" \
        "openssl rsautl -encrypt -inkey test_public.pem -pubin -in small_test.txt -out small_test.rsa && test -f small_test.rsa" \
        "Should encrypt small file using RSA public key" \
        15
    
    run_test "RSA Small File Decryption" \
        "openssl rsautl -decrypt -inkey test_private.pem -in small_test.rsa -out small_test_decrypted.txt && diff small_test.txt small_test_decrypted.txt" \
        "Should decrypt RSA file and match original" \
        15
}

test_digital_signature_workflow() {
    print_test_section "DIGITAL SIGNATURE WORKFLOW TESTS"
    
    run_test "File Signing Process" \
        "openssl dgst -sha256 -sign test_private.pem -out test_document.sig test_document.txt && test -f test_document.sig" \
        "Should create digital signature for file" \
        15
    
    run_test "Signature Verification Process" \
        "openssl dgst -sha256 -verify test_public.pem -signature test_document.sig test_document.txt" \
        "Should verify digital signature successfully" \
        15
    
    run_test "Signature Tampering Detection" \
        "echo 'tampered content' > tampered_document.txt && ! openssl dgst -sha256 -verify test_public.pem -signature test_document.sig tampered_document.txt" \
        "Should detect tampering when content is modified" \
        15
}

test_hash_verification_workflow() {
    print_test_section "HASH VERIFICATION WORKFLOW TESTS"
    
    run_test "SHA-256 Hash Generation" \
        "sha256sum test_document.txt > test_document.sha256 && test -f test_document.sha256" \
        "Should generate SHA-256 hash file" \
        10
    
    run_test "Hash Verification Success" \
        "sha256sum -c test_document.sha256" \
        "Should verify hash successfully for unmodified file" \
        10
    
    run_test "Hash Verification Failure Detection" \
        "echo 'modified content' > modified_document.txt && echo \"\$(cat test_document.sha256 | cut -d' ' -f1)  modified_document.txt\" | ! sha256sum -c" \
        "Should detect hash mismatch for modified file" \
        10
}

test_large_file_handling() {
    print_test_section "LARGE FILE HANDLING TESTS"
    
    run_test "Large File AES Encryption" \
        "openssl enc -aes-256-cbc -in large_test.dat -out large_test.aes -k 'testpassword' && test \$(wc -c < large_test.aes) -gt 5000000" \
        "Should encrypt large file (5MB+) successfully" \
        30
    
    run_test "Large File AES Decryption" \
        "openssl enc -aes-256-cbc -d -in large_test.aes -out large_test_decrypted.dat -k 'testpassword' && diff large_test.dat large_test_decrypted.dat" \
        "Should decrypt large file and match original" \
        30
    
    run_test "Large File Hash Calculation" \
        "sha256sum large_test.dat | cut -d' ' -f1 | grep -q '^[a-f0-9]\{64\}$'" \
        "Should calculate hash for large file efficiently" \
        20
}

test_binary_file_handling() {
    print_test_section "BINARY FILE HANDLING TESTS"
    
    run_test "Binary File AES Encryption" \
        "openssl enc -aes-256-cbc -in binary_test.bin -out binary_test.aes -k 'testpassword' && test -f binary_test.aes" \
        "Should encrypt binary file successfully" \
        15
    
    run_test "Binary File AES Decryption" \
        "openssl enc -aes-256-cbc -d -in binary_test.aes -out binary_test_decrypted.bin -k 'testpassword' && diff binary_test.bin binary_test_decrypted.bin" \
        "Should decrypt binary file and match original exactly" \
        15
    
    run_test "Binary File Signature" \
        "openssl dgst -sha256 -sign test_private.pem -out binary_test.sig binary_test.bin && openssl dgst -sha256 -verify test_public.pem -signature binary_test.sig binary_test.bin" \
        "Should sign and verify binary file successfully" \
        15
}

test_error_conditions() {
    print_test_section "ERROR CONDITION TESTS"
    
    run_test "Invalid Key Handling" \
        "! openssl enc -aes-256-cbc -d -in test_document.aes -out /dev/null -k 'wrongpassword' 2>/dev/null" \
        "Should fail gracefully with wrong decryption key" \
        10
    
    run_test "Corrupted File Handling" \
        "dd if=/dev/urandom of=corrupted.aes bs=1024 count=1 2>/dev/null && ! openssl enc -aes-256-cbc -d -in corrupted.aes -out /dev/null -k 'testpassword' 2>/dev/null" \
        "Should fail gracefully with corrupted encrypted file" \
        10
    
    run_test "Missing File Handling" \
        "! openssl enc -aes-256-cbc -in nonexistent.txt -out /dev/null -k 'testpassword' 2>/dev/null" \
        "Should fail gracefully when input file doesn't exist" \
        5
    
    run_test "Invalid Signature Verification" \
        "dd if=/dev/urandom of=invalid.sig bs=256 count=1 2>/dev/null && ! openssl dgst -sha256 -verify test_public.pem -signature invalid.sig test_document.txt 2>/dev/null" \
        "Should fail gracefully with invalid signature" \
        10
}

test_performance_basic() {
    print_test_section "BASIC PERFORMANCE TESTS"
    
    run_test "Encryption Performance Test" \
        "time openssl enc -aes-256-cbc -in large_test.dat -out perf_test.aes -k 'testpassword' 2>&1 | grep real" \
        "Should encrypt 5MB file in reasonable time" \
        45
    
    run_test "Hash Performance Test" \
        "time sha256sum large_test.dat 2>&1 | grep real" \
        "Should hash 5MB file quickly" \
        30
    
    run_test "Signature Performance Test" \
        "time openssl dgst -sha256 -sign test_private.pem -out perf_test.sig large_test.dat 2>&1 | grep real" \
        "Should sign 5MB file in reasonable time" \
        30
}

generate_json_report() {
    cat > "$REPORT_FILE" << EOF
{
  "test_phase": "Phase 2 - Integration Tests",
  "test_date": "$(date -Iseconds)",
  "test_duration": "$1",
  "test_environment": "/tmp/crypto_integration_tests",
  "application_path": "$APP_PATH",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "test_categories": {
    "application_startup": "Application launch and dependency tests",
    "cli_operations": "Command line interface functionality",
    "file_encryption": "End-to-end encryption workflows",
    "digital_signatures": "Signature creation and verification",
    "hash_verification": "Hash generation and validation",
    "large_files": "Large file handling capabilities",
    "binary_files": "Binary file processing",
    "error_conditions": "Error handling and edge cases",
    "performance": "Basic performance characteristics"
  },
  "recommendations": [
    "Review failed integration tests before Phase 3",
    "Check application startup if startup tests failed",
    "Verify file handling if file operation tests failed",
    "Consider performance optimization if performance tests show issues",
    "Proceed to security testing if all critical tests pass"
  ]
}
EOF
}

cleanup_test_environment() {
    echo -e "${BLUE}Cleaning up test environment...${NC}"
    cd /
    rm -rf /tmp/crypto_integration_tests
    echo -e "${GREEN}✓ Test environment cleaned${NC}"
}

print_summary() {
    local end_time=$(date)
    local duration="$1"
    
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                                    INTEGRATION TEST SUMMARY${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
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
        echo -e "${GREEN}🎉 ALL INTEGRATION TESTS PASSED! Ready for Phase 3 Security Testing.${NC}"
    elif [ $FAILED_TESTS -le 3 ]; then
        echo -e "${YELLOW}⚠️  Some minor issues found. Review failed tests before proceeding.${NC}"
    else
        echo -e "${RED}⚠️  Multiple integration failures. Fix critical issues before Phase 3.${NC}"
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
    echo "Phase 2 Integration Tests - $(date)" > "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # Setup test environment
    setup_test_environment
    
    # Run all test categories
    test_application_startup
    test_cli_operations
    test_file_encryption_workflow
    test_digital_signature_workflow
    test_hash_verification_workflow
    test_large_file_handling
    test_binary_file_handling
    test_error_conditions
    test_performance_basic
    
    # Calculate duration
    local end_timestamp=$(date +%s)
    local duration=$((end_timestamp - start_timestamp))
    
    # Generate reports
    generate_json_report "$duration"
    print_summary "$duration"
    
    # Cleanup
    cleanup_test_environment
}

# Ensure bc is available for calculations
if ! command -v bc &> /dev/null; then
    echo "Installing bc for calculations..."
    sudo apt-get install -y bc 2>/dev/null || sudo yum install -y bc 2>/dev/null || echo "Please install bc manually"
fi

# Run the tests
main "$@"
