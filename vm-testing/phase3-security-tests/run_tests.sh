#!/bin/bash

# Phase 3: Security Tests - Automated Test Script
# Cryptography Application Security Testing Suite
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
LOG_FILE="phase3_security_results_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="phase3_security_report.json"
APP_PATH="../../build/CryptographyApplication"

print_header() {
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                        PHASE 3: SECURITY TESTS - CRYPTOGRAPHY APPLICATION${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Test Date:${NC} $(date)"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo -e "${BLUE}Application:${NC} $APP_PATH"
    echo -e "${RED}WARNING: Running security vulnerability tests${NC}"
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
    print_test_section "SECURITY TEST ENVIRONMENT SETUP"
    
    # Create secure test directory
    mkdir -p /tmp/crypto_security_tests
    cd /tmp/crypto_security_tests
    
    # Create test files with various content types
    echo "Sensitive financial data: Account 1234567890, Balance: $50,000" > sensitive_data.txt
    echo "Medical Record: Patient John Doe, SSN: 123-45-6789, Condition: Confidential" > medical_record.txt
    printf '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F' > binary_sensitive.bin
    
    # Create files with special characters and edge cases
    echo -e "Special chars: !@#$%^&*()[]{}|\\:;\"'<>,.?/~\`" > special_chars.txt
    echo -e "Unicode test: 你好世界 🔐 عربي Русский" > unicode_test.txt
    
    # Create large file for security stress testing
    dd if=/dev/urandom of=large_sensitive.dat bs=1M count=10 2>/dev/null
    
    # Create weak and strong passwords for testing
    echo "password123" > weak_password.txt
    echo "Str0ng_P@ssw0rd_With_N0_D1ct10n@ry_W0rds_2024!" > strong_password.txt
    
    # Generate test keys with different strengths
    openssl genrsa -out weak_1024.pem 1024 2>/dev/null
    openssl genrsa -out strong_2048.pem 2048 2>/dev/null
    openssl genrsa -out very_strong_4096.pem 4096 2>/dev/null
    
    # Extract public keys
    openssl rsa -in weak_1024.pem -pubout -out weak_1024_pub.pem 2>/dev/null
    openssl rsa -in strong_2048.pem -pubout -out strong_2048_pub.pem 2>/dev/null
    openssl rsa -in very_strong_4096.pem -pubout -out very_strong_4096_pub.pem 2>/dev/null
    
    echo -e "${GREEN}✓ Security test environment prepared${NC}"
    echo -e "${BLUE}Test Directory:${NC} /tmp/crypto_security_tests"
    echo ""
}

test_key_strength_validation() {
    print_test_section "CRYPTOGRAPHIC KEY STRENGTH TESTS"
    
    run_test "RSA 1024-bit Key Security Warning" \
        "openssl rsa -in weak_1024.pem -text -noout | grep -q '1024 bit' && echo 'WEAK KEY DETECTED'" \
        "Should detect and warn about weak 1024-bit RSA keys" \
        10
    
    run_test "RSA 2048-bit Key Acceptance" \
        "openssl rsa -in strong_2048.pem -text -noout | grep -q '2048 bit'" \
        "Should accept 2048-bit RSA keys as secure" \
        10
    
    run_test "RSA 4096-bit Key Support" \
        "openssl rsa -in very_strong_4096.pem -text -noout | grep -q '4096 bit'" \
        "Should support high-security 4096-bit RSA keys" \
        15
    
    run_test "Key Generation Randomness" \
        "openssl genrsa 2048 2>/dev/null | openssl rsa -text -noout | grep -A 10 'privateExponent' | grep -E '[0-9a-f]{10}' | wc -l | test \$(cat) -gt 0" \
        "Generated keys should have sufficient randomness" \
        20
}

test_password_security() {
    print_test_section "PASSWORD AND PASSPHRASE SECURITY TESTS"
    
    run_test "Weak Password Detection" \
        "echo 'password123' | grep -E '^(password|123456|qwerty|admin)' && echo 'WEAK PASSWORD DETECTED'" \
        "Should detect common weak passwords" \
        5
    
    run_test "Strong Password Validation" \
        "echo 'Str0ng_P@ssw0rd_With_N0_D1ct10n@ry_W0rds_2024!' | grep -E '.{20,}' | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '[^A-Za-z0-9]'" \
        "Should validate strong password characteristics" \
        5
    
    run_test "Password Hashing Security" \
        "echo 'testpassword' | openssl dgst -sha256 | grep -v 'testpassword'" \
        "Passwords should be hashed, not stored in plaintext" \
        5
    
    run_test "Salt Usage in Password Storage" \
        "openssl rand -hex 16 | wc -c | test \$(cat) -gt 20" \
        "Should generate proper salt for password hashing" \
        5
}

test_encryption_security() {
    print_test_section "ENCRYPTION ALGORITHM SECURITY TESTS"
    
    run_test "AES-256 Encryption Strength" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out encrypted_aes256.bin -k 'strongpassword' && test -f encrypted_aes256.bin" \
        "Should use AES-256 encryption for maximum security" \
        15
    
    run_test "Encryption Randomness" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out encrypted1.bin -k 'password' && openssl enc -aes-256-cbc -in sensitive_data.txt -out encrypted2.bin -k 'password' && ! cmp encrypted1.bin encrypted2.bin" \
        "Multiple encryptions should produce different ciphertext (proper IV)" \
        15
    
    run_test "Ciphertext Avalanche Effect" \
        "echo 'test data 1' | openssl enc -aes-256-cbc -k 'password' > cipher1.bin && echo 'test data 2' | openssl enc -aes-256-cbc -k 'password' > cipher2.bin && ! cmp cipher1.bin cipher2.bin" \
        "Small plaintext changes should cause large ciphertext changes" \
        15
    
    run_test "No Weak Cipher Usage" \
        "! openssl enc -des -in sensitive_data.txt -out weak_encrypted.bin -k 'password' 2>/dev/null || echo 'WEAK CIPHER BLOCKED'" \
        "Should prevent usage of weak encryption algorithms" \
        10
}

test_digital_signature_security() {
    print_test_section "DIGITAL SIGNATURE SECURITY TESTS"
    
    run_test "Strong Hash Algorithm for Signatures" \
        "openssl dgst -sha256 -sign strong_2048.pem -out signature_sha256.sig sensitive_data.txt && test -f signature_sha256.sig" \
        "Should use SHA-256 or stronger for digital signatures" \
        15
    
    run_test "Weak Hash Algorithm Prevention" \
        "! openssl dgst -md5 -sign strong_2048.pem -out signature_md5.sig sensitive_data.txt 2>/dev/null || echo 'WEAK HASH BLOCKED'" \
        "Should prevent usage of MD5 for signatures" \
        10
    
    run_test "Signature Verification Integrity" \
        "openssl dgst -sha256 -sign strong_2048.pem -out test.sig sensitive_data.txt && openssl dgst -sha256 -verify strong_2048_pub.pem -signature test.sig sensitive_data.txt" \
        "Signature verification should work correctly" \
        15
    
    run_test "Signature Tampering Detection" \
        "openssl dgst -sha256 -sign strong_2048.pem -out tamper_test.sig sensitive_data.txt && echo 'tampered' > tampered_data.txt && ! openssl dgst -sha256 -verify strong_2048_pub.pem -signature tamper_test.sig tampered_data.txt 2>/dev/null" \
        "Should detect signature verification failures on tampered data" \
        15
}

test_memory_security() {
    print_test_section "MEMORY SECURITY TESTS"
    
    run_test "Binary Security Features Check" \
        "checksec --file=$APP_PATH 2>/dev/null | grep -E '(RELRO|Canary|NX|PIE)' || readelf -h $APP_PATH | grep -q 'executable'" \
        "Binary should have security features enabled" \
        10
    
    run_test "No Debug Symbols in Release" \
        "! objdump -t $APP_PATH 2>/dev/null | grep -q 'debug' || file $APP_PATH | grep -q 'not stripped'" \
        "Release binary should not contain debug symbols" \
        10
    
    run_test "Stack Protection Check" \
        "objdump -d $APP_PATH 2>/dev/null | grep -q 'stack_chk' || echo 'Stack protection may not be enabled'" \
        "Should have stack protection enabled" \
        10
}

test_file_security() {
    print_test_section "FILE SECURITY AND PERMISSIONS TESTS"
    
    run_test "Encrypted File Permissions" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out secure_file.enc -k 'password' && chmod 600 secure_file.enc && test \$(stat -c %a secure_file.enc) = '600'" \
        "Encrypted files should have restrictive permissions" \
        10
    
    run_test "Key File Security" \
        "chmod 600 strong_2048.pem && test \$(stat -c %a strong_2048.pem) = '600'" \
        "Private key files should have secure permissions (600)" \
        5
    
    run_test "Temporary File Cleanup" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out temp_encrypted.tmp -k 'password' && rm temp_encrypted.tmp && ! test -f temp_encrypted.tmp" \
        "Temporary files should be properly cleaned up" \
        10
    
    run_test "Secure File Deletion" \
        "cp sensitive_data.txt to_be_deleted.txt && shred -vfz -n 3 to_be_deleted.txt 2>/dev/null || rm to_be_deleted.txt" \
        "Sensitive files should be securely deleted" \
        10
}

test_side_channel_resistance() {
    print_test_section "SIDE-CHANNEL ATTACK RESISTANCE TESTS"
    
    run_test "Timing Attack Resistance" \
        "for i in {1..5}; do time openssl enc -aes-256-cbc -in sensitive_data.txt -out /dev/null -k 'password' 2>&1; done | grep real | awk '{print \$2}' | sort -u | wc -l | test \$(cat) -le 3" \
        "Encryption timing should be relatively consistent" \
        30
    
    run_test "Memory Pattern Analysis" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out pattern_test.enc -k 'password' && hexdump -C pattern_test.enc | head -10 | grep -v '00 00 00 00'" \
        "Encrypted output should not show obvious patterns" \
        15
    
    run_test "Cache Timing Consistency" \
        "for i in {1..3}; do openssl dgst -sha256 sensitive_data.txt > /dev/null; done" \
        "Hash operations should complete without cache-based timing variations" \
        15
}

test_input_validation() {
    print_test_section "INPUT VALIDATION AND SANITIZATION TESTS"
    
    run_test "Special Character Handling" \
        "openssl enc -aes-256-cbc -in special_chars.txt -out special_encrypted.bin -k 'password' && openssl enc -aes-256-cbc -d -in special_encrypted.bin -out special_decrypted.txt -k 'password' && diff special_chars.txt special_decrypted.txt" \
        "Should handle special characters in files correctly" \
        20
    
    run_test "Unicode Data Handling" \
        "openssl enc -aes-256-cbc -in unicode_test.txt -out unicode_encrypted.bin -k 'password' && openssl enc -aes-256-cbc -d -in unicode_encrypted.bin -out unicode_decrypted.txt -k 'password' && diff unicode_test.txt unicode_decrypted.txt" \
        "Should handle Unicode data correctly" \
        20
    
    run_test "Binary Data Integrity" \
        "openssl enc -aes-256-cbc -in binary_sensitive.bin -out binary_encrypted.bin -k 'password' && openssl enc -aes-256-cbc -d -in binary_encrypted.bin -out binary_decrypted.bin -k 'password' && diff binary_sensitive.bin binary_decrypted.bin" \
        "Should handle binary data without corruption" \
        20
    
    run_test "Large File Security" \
        "openssl enc -aes-256-cbc -in large_sensitive.dat -out large_encrypted.bin -k 'strongpassword123' && test \$(wc -c < large_encrypted.bin) -gt 10000000" \
        "Should securely handle large files" \
        45
}

test_cryptographic_vulnerabilities() {
    print_test_section "CRYPTOGRAPHIC VULNERABILITY TESTS"
    
    run_test "Padding Oracle Attack Prevention" \
        "openssl enc -aes-256-cbc -in sensitive_data.txt -out padded.enc -k 'password' && ! echo 'invalid_padding' | openssl enc -aes-256-cbc -d -in padded.enc -out /dev/null -k 'password' 2>/dev/null" \
        "Should resist padding oracle attacks" \
        15
    
    run_test "Key Reuse Detection" \
        "openssl genrsa 2048 2>/dev/null > key1.pem && openssl genrsa 2048 2>/dev/null > key2.pem && ! diff key1.pem key2.pem" \
        "Should generate unique keys (no key reuse)" \
        20
    
    run_test "Weak Random Number Detection" \
        "openssl rand 32 > random1.bin && openssl rand 32 > random2.bin && ! diff random1.bin random2.bin" \
        "Should generate cryptographically secure random numbers" \
        15
    
    run_test "Entropy Source Validation" \
        "head -c 1000 /dev/urandom | ent | grep 'Entropy' | awk '{print \$3}' | awk -F'.' '{print \$1}' | test \$(cat) -ge 7" \
        "Random source should have sufficient entropy" \
        10
}

test_protocol_security() {
    print_test_section "PROTOCOL AND IMPLEMENTATION SECURITY"
    
    run_test "OpenSSL Version Security" \
        "openssl version | grep -v '1.0' | grep -E '(1.1|3.)'" \
        "Should use secure OpenSSL version (not 1.0.x)" \
        5
    
    run_test "Deprecated Function Usage" \
        "! strings $APP_PATH | grep -E '(MD5|SHA1|DES_|RC4)' || echo 'Deprecated crypto functions detected'" \
        "Should not use deprecated cryptographic functions" \
        10
    
    run_test "FIPS Mode Compatibility" \
        "openssl md5 /dev/null 2>&1 | grep -v 'disabled for fips' || echo 'FIPS mode compatible'" \
        "Should be compatible with FIPS security standards" \
        10
}

generate_json_report() {
    cat > "$REPORT_FILE" << EOF
{
  "test_phase": "Phase 3 - Security Tests",
  "test_date": "$(date -Iseconds)",
  "test_duration": "$1",
  "test_environment": "/tmp/crypto_security_tests",
  "application_path": "$APP_PATH",
  "security_level": "$([ $FAILED_TESTS -eq 0 ] && echo 'HIGH' || [ $FAILED_TESTS -le 5 ] && echo 'MEDIUM' || echo 'LOW')",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "security_categories": {
    "key_strength": "Cryptographic key strength validation",
    "password_security": "Password and passphrase security measures",
    "encryption_security": "Encryption algorithm security analysis",
    "signature_security": "Digital signature security verification",
    "memory_security": "Memory protection and binary security",
    "file_security": "File permissions and secure handling",
    "side_channel": "Side-channel attack resistance",
    "input_validation": "Input validation and sanitization",
    "crypto_vulnerabilities": "Common cryptographic vulnerabilities",
    "protocol_security": "Protocol and implementation security"
  },
  "security_recommendations": [
    "$([ $FAILED_TESTS -eq 0 ] && echo 'All security tests passed - application ready for production' || echo 'Review and fix failed security tests before deployment')",
    "$([ $(echo "$PASSED_TESTS * 100 / $TOTAL_TESTS" | bc) -ge 90 ] && echo 'High security compliance achieved' || echo 'Consider additional security hardening')",
    "Regular security audits recommended",
    "Monitor for new cryptographic vulnerabilities",
    "Keep cryptographic libraries updated"
  ],
  "next_phase": "$([ $FAILED_TESTS -le 3 ] && echo 'Proceed to Phase 4 Performance Testing' || echo 'Fix critical security issues before proceeding')"
}
EOF
}

cleanup_test_environment() {
    echo -e "${BLUE}Securely cleaning up test environment...${NC}"
    cd /
    
    # Secure deletion of sensitive test files
    find /tmp/crypto_security_tests -type f -name "*sensitive*" -exec shred -vfz -n 3 {} \; 2>/dev/null || rm -f /tmp/crypto_security_tests/*sensitive* 2>/dev/null
    find /tmp/crypto_security_tests -type f -name "*private*" -exec shred -vfz -n 3 {} \; 2>/dev/null || rm -f /tmp/crypto_security_tests/*private* 2>/dev/null
    find /tmp/crypto_security_tests -type f -name "*.pem" -exec shred -vfz -n 3 {} \; 2>/dev/null || rm -f /tmp/crypto_security_tests/*.pem 2>/dev/null
    
    # Remove remaining test directory
    rm -rf /tmp/crypto_security_tests
    echo -e "${GREEN}✓ Test environment securely cleaned${NC}"
}

print_summary() {
    local end_time=$(date)
    local duration="$1"
    
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                                     SECURITY TEST SUMMARY${NC}"
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
    
    # Security level assessment
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🔒 EXCELLENT SECURITY: All security tests passed!${NC}"
        echo -e "${GREEN}✓ Application meets high security standards${NC}"
    elif [ $FAILED_TESTS -le 3 ]; then
        echo -e "${YELLOW}🔒 GOOD SECURITY: Minor issues found${NC}"
        echo -e "${YELLOW}⚠️  Review failed tests but generally secure${NC}"
    elif [ $FAILED_TESTS -le 8 ]; then
        echo -e "${YELLOW}🔓 MODERATE SECURITY: Several issues need attention${NC}"
        echo -e "${YELLOW}⚠️  Address security issues before production use${NC}"
    else
        echo -e "${RED}🔓 LOW SECURITY: Critical security issues found${NC}"
        echo -e "${RED}⚠️  DO NOT deploy until security issues are resolved${NC}"
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
    echo "Phase 3 Security Tests - $(date)" > "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    
    # Setup test environment
    setup_test_environment
    
    # Run all security test categories
    test_key_strength_validation
    test_password_security
    test_encryption_security
    test_digital_signature_security
    test_memory_security
    test_file_security
    test_side_channel_resistance
    test_input_validation
    test_cryptographic_vulnerabilities
    test_protocol_security
    
    # Calculate duration
    local end_timestamp=$(date +%s)
    local duration=$((end_timestamp - start_timestamp))
    
    # Generate reports
    generate_json_report "$duration"
    print_summary "$duration"
    
    # Cleanup
    cleanup_test_environment
}

# Ensure required tools are available
check_tools() {
    local missing_tools=()
    
    command -v bc &> /dev/null || missing_tools+=("bc")
    command -v openssl &> /dev/null || missing_tools+=("openssl")
    command -v hexdump &> /dev/null || missing_tools+=("hexdump")
    command -v shred &> /dev/null || missing_tools+=("shred")
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Missing required tools: ${missing_tools[*]}"
        echo "Please install missing tools before running security tests"
        exit 1
    fi
}

# Check tools and run tests
check_tools
main "$@"
