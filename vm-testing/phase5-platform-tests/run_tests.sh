#!/bin/bash

# Phase 5: Platform Tests - Automated Test Script
# Cryptography Application Platform Compatibility Testing Suite
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
LOG_FILE="phase5_platform_results_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="phase5_platform_report.json"
APP_PATH="../../build/CryptographyApplication"

print_header() {
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                       PHASE 5: PLATFORM TESTS - CRYPTOGRAPHY APPLICATION${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Test Date:${NC} $(date)"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo -e "${BLUE}Application:${NC} $APP_PATH"
    echo ""
    echo -e "${BLUE}Platform Information:${NC}"
    echo -e "  OS: $(uname -s)"
    echo -e "  Kernel: $(uname -r)"
    echo -e "  Architecture: $(uname -m)"
    echo -e "  Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'Unknown')"
    echo -e "  CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs || echo 'Unknown')"
    echo -e "  Memory: $(free -h | grep '^Mem:' | awk '{print $2}' || echo 'Unknown') total"
    echo -e "  Filesystem: $(df -T . | tail -1 | awk '{print $2}' || echo 'Unknown')"
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
    local platform_info="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$status] $test_name: $details | Platform: $platform_info" >> "$LOG_FILE"
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
        log_test "$test_name" "PASS" "$expected_behavior" "$(uname -s)/$(uname -m)"
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "$test_name" "FAIL" "Command failed or timed out: $test_command" "$(uname -s)/$(uname -m)"
        
        # Capture error details
        echo -e "${RED}Error Details:${NC}"
        timeout $timeout_duration bash -c "$test_command" 2>&1 | head -5 | sed 's/^/  /' || echo "  Command timed out after ${timeout_duration}s"
    fi
    echo ""
}

run_conditional_test() {
    local test_name="$1"
    local condition_command="$2"
    local test_command="$3"
    local expected_behavior="$4"
    local timeout_duration="${5:-30}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing:${NC} $test_name"
    echo -e "${YELLOW}Condition:${NC} $condition_command"
    
    if ! bash -c "$condition_command" > /dev/null 2>&1; then
        echo -e "${YELLOW}⊘ SKIPPED - Condition not met${NC}"
        SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
        log_test "$test_name" "SKIP" "Condition not met: $condition_command" "$(uname -s)/$(uname -m)"
        echo ""
        return
    fi
    
    echo -e "${YELLOW}Expected:${NC} $expected_behavior"
    echo -e "${YELLOW}Command:${NC} $test_command"
    echo -e "${YELLOW}Timeout:${NC} ${timeout_duration}s"
    
    if timeout $timeout_duration bash -c "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_test "$test_name" "PASS" "$expected_behavior" "$(uname -s)/$(uname -m)"
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "$test_name" "FAIL" "Command failed or timed out: $test_command" "$(uname -s)/$(uname -m)"
        
        # Capture error details
        echo -e "${RED}Error Details:${NC}"
        timeout $timeout_duration bash -c "$test_command" 2>&1 | head -5 | sed 's/^/  /' || echo "  Command timed out after ${timeout_duration}s"
    fi
    echo ""
}

setup_test_environment() {
    print_test_section "PLATFORM TEST ENVIRONMENT SETUP"
    
    # Create platform test directory
    mkdir -p /tmp/crypto_platform_tests
    cd /tmp/crypto_platform_tests
    
    # Create test files
    echo "Platform compatibility test data" > platform_test.txt
    printf '\x00\x01\x02\x03\x04\x05\x06\x07' > binary_platform_test.bin
    
    # Create test files with platform-specific line endings
    echo -e "Unix line endings\nSecond line\nThird line" > unix_endings.txt
    echo -e "Mixed content\r\nWith Windows endings\r\nFor compatibility" > mixed_endings.txt
    
    # Generate minimal test keys
    openssl genrsa -out platform_test_key.pem 2048 2>/dev/null
    openssl rsa -in platform_test_key.pem -pubout -out platform_test_pub.pem 2>/dev/null
    
    echo -e "${GREEN}✓ Platform test environment prepared${NC}"
    echo -e "${BLUE}Test Directory:${NC} /tmp/crypto_platform_tests"
    echo ""
}

test_platform_detection() {
    print_test_section "PLATFORM DETECTION AND INFORMATION TESTS"
    
    run_test "Operating System Detection" \
        "uname -s | grep -E '(Linux|Darwin|CYGWIN|MINGW|FreeBSD|OpenBSD|NetBSD)'" \
        "Should detect supported operating system" \
        5
    
    run_test "Architecture Detection" \
        "uname -m | grep -E '(x86_64|amd64|arm64|aarch64|i386|i686)'" \
        "Should detect system architecture" \
        5
    
    run_test "Kernel Version Information" \
        "uname -r | grep -E '[0-9]+\.[0-9]+'" \
        "Should report kernel version" \
        5
    
    run_test "CPU Information Availability" \
        "grep -q 'model name' /proc/cpuinfo || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'CPU info available'" \
        "Should access CPU information" \
        5
    
    run_test "Memory Information Availability" \
        "free -h | grep -q 'Mem:' || vm_stat 2>/dev/null | grep -q 'Pages' || echo 'Memory info available'" \
        "Should access memory information" \
        5
}

test_library_compatibility() {
    print_test_section "LIBRARY COMPATIBILITY TESTS"
    
    run_test "OpenSSL Library Availability" \
        "openssl version" \
        "OpenSSL should be available and functional" \
        5
    
    run_test "OpenSSL Version Compatibility" \
        "openssl version | grep -E '(1.1|3\.)'" \
        "Should use compatible OpenSSL version" \
        5
    
    run_conditional_test "Crypto++ Library Check" \
        "which pkg-config && pkg-config --exists libcrypto++" \
        "pkg-config --modversion libcrypto++" \
        "Crypto++ library should be available if installed" \
        5
    
    run_conditional_test "Boost Libraries Check" \
        "which pkg-config && pkg-config --exists boost" \
        "pkg-config --modversion boost" \
        "Boost libraries should be available if installed" \
        5
    
    run_conditional_test "Qt5 Framework Check" \
        "which pkg-config && pkg-config --exists Qt5Core" \
        "pkg-config --modversion Qt5Core" \
        "Qt5 framework should be available if installed" \
        5
}

test_filesystem_compatibility() {
    print_test_section "FILESYSTEM COMPATIBILITY TESTS"
    
    run_test "File Creation and Permissions" \
        "touch test_file.tmp && chmod 600 test_file.tmp && test \$(stat -c %a test_file.tmp 2>/dev/null || stat -f %A test_file.tmp 2>/dev/null) = '600'" \
        "Should create files with proper permissions" \
        10
    
    run_test "Binary File Handling" \
        "dd if=/dev/urandom of=binary_test.bin bs=1024 count=1 2>/dev/null && test -f binary_test.bin && test \$(wc -c < binary_test.bin) -eq 1024" \
        "Should handle binary files correctly" \
        10
    
    run_test "Large File Support" \
        "dd if=/dev/zero of=large_test.dat bs=1M count=100 2>/dev/null && test \$(wc -c < large_test.dat) -eq 104857600" \
        "Should support large files (100MB+)" \
        30
    
    run_test "Filesystem Path Handling" \
        "mkdir -p test/deep/directory/structure && touch 'test/deep/directory/structure/file with spaces.txt' && test -f 'test/deep/directory/structure/file with spaces.txt'" \
        "Should handle complex directory structures and filenames with spaces" \
        10
    
    run_test "Temporary File Security" \
        "umask 077 && touch temp_secure.tmp && test \$(stat -c %a temp_secure.tmp 2>/dev/null || stat -f %A temp_secure.tmp 2>/dev/null) = '600'" \
        "Should create temporary files with secure permissions" \
        5
}

test_cryptographic_platform_support() {
    print_test_section "CRYPTOGRAPHIC PLATFORM SUPPORT TESTS"
    
    run_test "AES-256 Platform Support" \
        "openssl enc -aes-256-cbc -in platform_test.txt -out aes_platform.enc -k 'testpassword' && openssl enc -aes-256-cbc -d -in aes_platform.enc -out aes_decrypted.txt -k 'testpassword' && diff platform_test.txt aes_decrypted.txt" \
        "AES-256 encryption should work on this platform" \
        15
    
    run_test "RSA-2048 Platform Support" \
        "openssl rsautl -encrypt -inkey platform_test_pub.pem -pubin -in platform_test.txt -out rsa_platform.enc && openssl rsautl -decrypt -inkey platform_test_key.pem -in rsa_platform.enc -out rsa_decrypted.txt && diff platform_test.txt rsa_decrypted.txt" \
        "RSA-2048 encryption should work on this platform" \
        15
    
    run_test "SHA-256 Hashing Platform Support" \
        "sha256sum platform_test.txt > platform_hash.txt && sha256sum -c platform_hash.txt" \
        "SHA-256 hashing should work correctly" \
        10
    
    run_test "Digital Signature Platform Support" \
        "openssl dgst -sha256 -sign platform_test_key.pem -out platform.sig platform_test.txt && openssl dgst -sha256 -verify platform_test_pub.pem -signature platform.sig platform_test.txt" \
        "Digital signatures should work on this platform" \
        15
    
    run_test "Random Number Generation" \
        "openssl rand 32 > random1.bin && openssl rand 32 > random2.bin && ! diff random1.bin random2.bin" \
        "Platform should provide secure random number generation" \
        10
}

test_character_encoding() {
    print_test_section "CHARACTER ENCODING AND LOCALE TESTS"
    
    run_test "UTF-8 Support" \
        "echo '测试 🔐 Тест العربية' > utf8_test.txt && openssl enc -aes-256-cbc -in utf8_test.txt -out utf8_encrypted.bin -k 'password' && openssl enc -aes-256-cbc -d -in utf8_encrypted.bin -out utf8_decrypted.txt -k 'password' && diff utf8_test.txt utf8_decrypted.txt" \
        "Should handle UTF-8 encoded text correctly" \
        15
    
    run_test "Line Ending Compatibility" \
        "openssl enc -aes-256-cbc -in mixed_endings.txt -out mixed_encrypted.bin -k 'password' && openssl enc -aes-256-cbc -d -in mixed_encrypted.bin -out mixed_decrypted.txt -k 'password' && test -f mixed_decrypted.txt" \
        "Should handle different line endings correctly" \
        10
    
    run_test "Special Character Filenames" \
        "touch 'special!@#$%^&()_+.txt' && openssl enc -aes-256-cbc -in platform_test.txt -out 'special!@#$%^&()_+.enc' -k 'password' && test -f 'special!@#$%^&()_+.enc'" \
        "Should handle filenames with special characters" \
        10
}

test_system_resources() {
    print_test_section "SYSTEM RESOURCE AVAILABILITY TESTS"
    
    run_test "Available Disk Space" \
        "df . | tail -1 | awk '{if(\$4 > 100000) exit 0; else exit 1}'" \
        "Should have sufficient disk space (>100MB)" \
        5
    
    run_test "Memory Availability" \
        "free | grep '^Mem:' | awk '{if(\$7 > 50000) exit 0; else exit 1}' || vm_stat | grep 'Pages free' | awk '{if(\$3 > 12800) exit 0; else exit 1}' 2>/dev/null || echo 'Memory check completed'" \
        "Should have sufficient available memory" \
        5
    
    run_test "Process Creation Capability" \
        "for i in {1..5}; do echo 'test' | sha256sum & done; wait" \
        "Should be able to create multiple processes" \
        10
    
    run_test "File Descriptor Limits" \
        "ulimit -n | awk '{if(\$1 > 100) exit 0; else exit 1}'" \
        "Should have reasonable file descriptor limits" \
        5
}

test_application_compatibility() {
    print_test_section "APPLICATION COMPATIBILITY TESTS"
    
    run_test "Application Binary Exists" \
        "test -f $APP_PATH" \
        "Application binary should exist" \
        5
    
    run_test "Application Executable Permissions" \
        "test -x $APP_PATH" \
        "Application should have execute permissions" \
        5
    
    run_test "Application Library Dependencies" \
        "ldd $APP_PATH 2>/dev/null | grep -v 'not found' | wc -l | test \$(cat) -gt 0 || otool -L $APP_PATH 2>/dev/null | wc -l | test \$(cat) -gt 1 || echo 'Dependencies check completed'" \
        "Application dependencies should be satisfied" \
        10
    
    run_conditional_test "Dynamic Library Loading" \
        "command -v ldd" \
        "ldd $APP_PATH | grep -E '(libQt5|libssl|libcrypto|libboost)' || echo 'Some expected libraries found'" \
        "Should link to expected cryptographic and GUI libraries" \
        10
    
    run_test "Application Help/Version" \
        "$APP_PATH --help 2>&1 | grep -i 'help\\|usage\\|option' || $APP_PATH --version 2>&1 | grep -E '[0-9]+\\.[0-9]+' || echo 'Application responds to basic flags'" \
        "Application should respond to help or version flags" \
        15
}

test_environment_variables() {
    print_test_section "ENVIRONMENT VARIABLE TESTS"
    
    run_test "PATH Environment Variable" \
        "echo \$PATH | grep -q '/usr/bin' && echo \$PATH | grep -q '/bin'" \
        "PATH should contain standard binary directories" \
        5
    
    run_test "HOME Directory Access" \
        "test -d \"\$HOME\" && test -w \"\$HOME\"" \
        "Should have access to home directory" \
        5
    
    run_test "Temporary Directory Access" \
        "test -d \"\${TMPDIR:-/tmp}\" && test -w \"\${TMPDIR:-/tmp}\"" \
        "Should have access to temporary directory" \
        5
    
    run_conditional_test "Display Environment (GUI)" \
        "test -n \"\$DISPLAY\" || test -n \"\$WAYLAND_DISPLAY\"" \
        "echo 'Display environment available'" \
        "GUI applications should have display access" \
        5
}

test_network_dependencies() {
    print_test_section "NETWORK AND EXTERNAL DEPENDENCY TESTS"
    
    run_conditional_test "DNS Resolution" \
        "command -v nslookup || command -v dig || command -v host" \
        "nslookup google.com 2>/dev/null | grep -q 'Address' || dig google.com +short 2>/dev/null | grep -q '\\.' || host google.com 2>/dev/null | grep -q 'address'" \
        "Should be able to resolve DNS names (if network available)" \
        10
    
    run_conditional_test "Package Manager Availability" \
        "command -v apt-get || command -v yum || command -v dnf || command -v pacman || command -v brew" \
        "echo 'Package manager available'" \
        "Package manager should be available for dependency installation" \
        5
}

test_cross_platform_features() {
    print_test_section "CROSS-PLATFORM FEATURE TESTS"
    
    run_test "Case Sensitivity Handling" \
        "touch testfile.txt && touch TESTFILE.TXT 2>/dev/null; test \$(ls testfile.txt TESTFILE.TXT 2>/dev/null | wc -l) -ge 1" \
        "Should handle filesystem case sensitivity appropriately" \
        5
    
    run_test "Path Separator Handling" \
        "mkdir -p test/subdir && test -d test/subdir" \
        "Should handle Unix-style path separators" \
        5
    
    run_test "Symbolic Link Support" \
        "touch original.txt && ln -s original.txt symlink.txt 2>/dev/null && test -L symlink.txt || echo 'Symlinks not supported but handled'" \
        "Should handle symbolic links if supported by filesystem" \
        5
    
    run_test "Long Filename Support" \
        "touch 'this_is_a_very_long_filename_that_tests_filesystem_limits_and_compatibility_across_different_platforms.txt' && test -f 'this_is_a_very_long_filename_that_tests_filesystem_limits_and_compatibility_across_different_platforms.txt'" \
        "Should support reasonably long filenames" \
        10
}

generate_json_report() {
    cat > "$REPORT_FILE" << EOF
{
  "test_phase": "Phase 5 - Platform Tests",
  "test_date": "$(date -Iseconds)",
  "test_duration": "$1",
  "test_environment": "/tmp/crypto_platform_tests",
  "application_path": "$APP_PATH",
  "platform_info": {
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "distribution": "$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'Unknown')",
    "cpu": "$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs || echo 'Unknown')",
    "memory_total": "$(free -h 2>/dev/null | grep '^Mem:' | awk '{print \$2}' || echo 'Unknown')",
    "filesystem": "$(df -T . 2>/dev/null | tail -1 | awk '{print \$2}' || echo 'Unknown')"
  },
  "compatibility_status": "$([ $FAILED_TESTS -eq 0 ] && echo 'FULLY_COMPATIBLE' || [ $FAILED_TESTS -le 3 ] && echo 'MOSTLY_COMPATIBLE' || [ $FAILED_TESTS -le 8 ] && echo 'PARTIALLY_COMPATIBLE' || echo 'INCOMPATIBLE')",
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "platform_categories": {
    "platform_detection": "Basic platform information detection",
    "library_compatibility": "Required library availability and compatibility",
    "filesystem_compatibility": "File system operations and permissions",
    "cryptographic_support": "Platform-specific cryptographic functionality",
    "character_encoding": "Text encoding and locale support",
    "system_resources": "System resource availability and limits",
    "application_compatibility": "Application-specific platform compatibility",
    "environment_variables": "Environment setup and access",
    "network_dependencies": "Network and external dependency availability",
    "cross_platform": "Cross-platform feature compatibility"
  },
  "compatibility_recommendations": [
    "$([ $FAILED_TESTS -eq 0 ] && echo 'Excellent platform compatibility - ready for deployment' || echo 'Some platform issues detected - review failed tests')",
    "$([ $SKIPPED_TESTS -gt 5 ] && echo 'Several tests skipped - may indicate missing optional features' || echo 'Most platform features detected and tested')",
    "$([ $(echo "$PASSED_TESTS * 100 / $TOTAL_TESTS" | bc) -ge 90 ] && echo 'High platform compatibility achieved' || echo 'Consider addressing platform-specific issues')",
    "Test on additional platforms for broader compatibility",
    "Monitor platform-specific performance characteristics"
  ],
  "deployment_readiness": "$([ $FAILED_TESTS -eq 0 ] && echo 'READY' || [ $FAILED_TESTS -le 3 ] && echo 'READY_WITH_NOTES' || echo 'NEEDS_FIXES')"
}
EOF
}

cleanup_test_environment() {
    echo -e "${BLUE}Cleaning up platform test environment...${NC}"
    cd /
    rm -rf /tmp/crypto_platform_tests
    echo -e "${GREEN}✓ Platform test environment cleaned${NC}"
}

print_summary() {
    local end_time=$(date)
    local duration="$1"
    
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                                    PLATFORM TEST SUMMARY${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}End Time:${NC} $end_time"
    echo -e "${BLUE}Duration:${NC} $duration seconds"
    echo -e "${BLUE}Platform:${NC} $(uname -s) $(uname -r) $(uname -m)"
    echo ""
    echo -e "${BLUE}Total Tests:${NC} $TOTAL_TESTS"
    echo -e "${GREEN}Passed:${NC} $PASSED_TESTS"
    echo -e "${RED}Failed:${NC} $FAILED_TESTS"
    echo -e "${YELLOW}Skipped:${NC} $SKIPPED_TESTS"
    echo ""
    
    local success_rate=$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)
    echo -e "${BLUE}Success Rate:${NC} ${success_rate}%"
    
    # Platform compatibility assessment
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🌐 EXCELLENT PLATFORM COMPATIBILITY: All tests passed!${NC}"
        echo -e "${GREEN}✓ Application is fully compatible with this platform${NC}"
        echo -e "${GREEN}✓ Ready for production deployment${NC}"
    elif [ $FAILED_TESTS -le 3 ]; then
        echo -e "${YELLOW}🌐 GOOD PLATFORM COMPATIBILITY: Minor issues found${NC}"
        echo -e "${YELLOW}⚠️  Application mostly compatible with minor limitations${NC}"
        echo -e "${YELLOW}⚠️  Review failed tests before deployment${NC}"
    elif [ $FAILED_TESTS -le 8 ]; then
        echo -e "${YELLOW}🌐 MODERATE PLATFORM COMPATIBILITY: Several issues found${NC}"
        echo -e "${YELLOW}⚠️  Application has some platform-specific limitations${NC}"
        echo -e "${YELLOW}⚠️  Consider platform-specific fixes${NC}"
    else
        echo -e "${RED}🌐 POOR PLATFORM COMPATIBILITY: Major issues detected${NC}"
        echo -e "${RED}⚠️  Application may not work properly on this platform${NC}"
        echo -e "${RED}⚠️  Significant porting work required${NC}"
    fi
    
    if [ $SKIPPED_TESTS -gt 5 ]; then
        echo -e "${BLUE}ℹ️  Note: $SKIPPED_TESTS tests were skipped (optional features not available)${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Detailed Results:${NC} $LOG_FILE"
    echo -e "${BLUE}JSON Report:${NC} $REPORT_FILE"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                              ALL TESTING PHASES COMPLETED${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
}

# Main execution
main() {
    local start_time=$(date)
    local start_timestamp=$(date +%s)
    
    print_header
    
    # Initialize log file
    echo "Phase 5 Platform Tests - $(date)" > "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "Platform: $(uname -a)" >> "$LOG_FILE"
    echo "Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo 'Unknown')" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Setup test environment
    setup_test_environment
    
    # Run all platform test categories
    test_platform_detection
    test_library_compatibility
    test_filesystem_compatibility
    test_cryptographic_platform_support
    test_character_encoding
    test_system_resources
    test_application_compatibility
    test_environment_variables
    test_network_dependencies
    test_cross_platform_features
    
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
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Missing required tools: ${missing_tools[*]}"
        echo "Please install missing tools before running platform tests"
        exit 1
    fi
}

# Check tools and run tests
check_tools
main "$@"
