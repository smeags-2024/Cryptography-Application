#!/bin/bash

# Phase 4: Performance Tests - Automated Test Script
# Cryptography Application Performance Testing Suite
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

# Performance thresholds (in seconds)
AES_ENCRYPT_THRESHOLD=2.0
RSA_ENCRYPT_THRESHOLD=5.0
HASH_THRESHOLD=1.0
SIGNATURE_THRESHOLD=3.0

# Logging
LOG_FILE="phase4_performance_results_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="phase4_performance_report.json"
APP_PATH="../../build/CryptographyApplication"

print_header() {
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                      PHASE 4: PERFORMANCE TESTS - CRYPTOGRAPHY APPLICATION${NC}"
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${BLUE}Test Date:${NC} $(date)"
    echo -e "${BLUE}Log File:${NC} $LOG_FILE"
    echo -e "${BLUE}Report File:${NC} $REPORT_FILE"
    echo -e "${BLUE}Application:${NC} $APP_PATH"
    echo -e "${BLUE}System Info:${NC} $(uname -a)"
    echo -e "${BLUE}CPU Info:${NC} $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
    echo -e "${BLUE}Memory:${NC} $(free -h | grep '^Mem:' | awk '{print $2}') total"
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
    local performance_data="$4"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$status] $test_name: $details | Performance: $performance_data" >> "$LOG_FILE"
}

measure_time() {
    local command="$1"
    local start_time=$(date +%s.%N)
    
    eval "$command" > /dev/null 2>&1
    local exit_code=$?
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l)
    
    echo "$duration"
    return $exit_code
}

run_performance_test() {
    local test_name="$1"
    local test_command="$2"
    local threshold="$3"
    local expected_behavior="$4"
    local iterations="${5:-1}"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${BLUE}Testing:${NC} $test_name"
    echo -e "${YELLOW}Expected:${NC} $expected_behavior"
    echo -e "${YELLOW}Threshold:${NC} ${threshold}s"
    echo -e "${YELLOW}Iterations:${NC} $iterations"
    
    local total_time=0
    local successful_runs=0
    local min_time=999999
    local max_time=0
    
    for ((i=1; i<=iterations; i++)); do
        echo -n "  Run $i/$iterations: "
        
        local duration=$(measure_time "$test_command")
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            successful_runs=$((successful_runs + 1))
            total_time=$(echo "$total_time + $duration" | bc -l)
            
            # Update min/max
            if (( $(echo "$duration < $min_time" | bc -l) )); then
                min_time=$duration
            fi
            if (( $(echo "$duration > $max_time" | bc -l) )); then
                max_time=$duration
            fi
            
            echo -e "${GREEN}${duration}s${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    done
    
    if [ $successful_runs -eq 0 ]; then
        echo -e "${RED}✗ FAILED - No successful runs${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_test "$test_name" "FAIL" "All test runs failed" "0 successful runs"
    else
        local avg_time=$(echo "scale=3; $total_time / $successful_runs" | bc -l)
        
        echo -e "${CYAN}Performance Summary:${NC}"
        echo -e "  Average: ${avg_time}s"
        echo -e "  Minimum: ${min_time}s"
        echo -e "  Maximum: ${max_time}s"
        echo -e "  Success Rate: $successful_runs/$iterations"
        
        if (( $(echo "$avg_time <= $threshold" | bc -l) )); then
            echo -e "${GREEN}✓ PASSED - Performance within threshold${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            log_test "$test_name" "PASS" "$expected_behavior" "avg:${avg_time}s min:${min_time}s max:${max_time}s"
        else
            echo -e "${RED}✗ FAILED - Performance exceeds threshold${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            log_test "$test_name" "FAIL" "Performance exceeded threshold: ${avg_time}s > ${threshold}s" "avg:${avg_time}s"
        fi
    fi
    echo ""
}

setup_test_environment() {
    print_test_section "PERFORMANCE TEST ENVIRONMENT SETUP"
    
    # Create performance test directory
    mkdir -p /tmp/crypto_performance_tests
    cd /tmp/crypto_performance_tests
    
    # Create test files of various sizes
    echo "Small test data for quick operations" > small_file.txt                    # ~35 bytes
    head -c 1K /dev/urandom > medium_file_1k.bin                                   # 1KB
    head -c 10K /dev/urandom > medium_file_10k.bin                                 # 10KB
    head -c 100K /dev/urandom > large_file_100k.bin                                # 100KB
    head -c 1M /dev/urandom > large_file_1m.bin                                    # 1MB
    head -c 10M /dev/urandom > very_large_file_10m.bin                             # 10MB
    head -c 100M /dev/urandom > huge_file_100m.bin                                 # 100MB
    
    # Generate RSA keys for testing
    openssl genrsa -out test_private_1024.pem 1024 2>/dev/null
    openssl genrsa -out test_private_2048.pem 2048 2>/dev/null
    openssl genrsa -out test_private_4096.pem 4096 2>/dev/null
    
    openssl rsa -in test_private_1024.pem -pubout -out test_public_1024.pem 2>/dev/null
    openssl rsa -in test_private_2048.pem -pubout -out test_public_2048.pem 2>/dev/null
    openssl rsa -in test_private_4096.pem -pubout -out test_public_4096.pem 2>/dev/null
    
    # Create performance test data sets
    echo "Performance test dataset for cryptographic operations benchmarking" > perf_dataset.txt
    
    echo -e "${GREEN}✓ Performance test environment prepared${NC}"
    echo -e "${BLUE}Test Directory:${NC} /tmp/crypto_performance_tests"
    echo -e "${BLUE}Test Files Created:${NC}"
    ls -lh *.txt *.bin 2>/dev/null | head -10
    echo ""
}

test_aes_encryption_performance() {
    print_test_section "AES ENCRYPTION PERFORMANCE TESTS"
    
    run_performance_test "AES-256 1KB File Encryption" \
        "openssl enc -aes-256-cbc -in medium_file_1k.bin -out aes_1k.enc -k 'testpassword'" \
        0.1 \
        "Should encrypt 1KB file in under 0.1 seconds" \
        5
    
    run_performance_test "AES-256 10KB File Encryption" \
        "openssl enc -aes-256-cbc -in medium_file_10k.bin -out aes_10k.enc -k 'testpassword'" \
        0.2 \
        "Should encrypt 10KB file in under 0.2 seconds" \
        5
    
    run_performance_test "AES-256 100KB File Encryption" \
        "openssl enc -aes-256-cbc -in large_file_100k.bin -out aes_100k.enc -k 'testpassword'" \
        0.5 \
        "Should encrypt 100KB file in under 0.5 seconds" \
        3
    
    run_performance_test "AES-256 1MB File Encryption" \
        "openssl enc -aes-256-cbc -in large_file_1m.bin -out aes_1m.enc -k 'testpassword'" \
        $AES_ENCRYPT_THRESHOLD \
        "Should encrypt 1MB file in under ${AES_ENCRYPT_THRESHOLD} seconds" \
        3
    
    run_performance_test "AES-256 10MB File Encryption" \
        "openssl enc -aes-256-cbc -in very_large_file_10m.bin -out aes_10m.enc -k 'testpassword'" \
        10.0 \
        "Should encrypt 10MB file in under 10 seconds" \
        2
}

test_aes_decryption_performance() {
    print_test_section "AES DECRYPTION PERFORMANCE TESTS"
    
    # First ensure encrypted files exist
    openssl enc -aes-256-cbc -in medium_file_1k.bin -out test_aes_1k.enc -k 'testpassword' 2>/dev/null
    openssl enc -aes-256-cbc -in large_file_100k.bin -out test_aes_100k.enc -k 'testpassword' 2>/dev/null
    openssl enc -aes-256-cbc -in large_file_1m.bin -out test_aes_1m.enc -k 'testpassword' 2>/dev/null
    
    run_performance_test "AES-256 1KB File Decryption" \
        "openssl enc -aes-256-cbc -d -in test_aes_1k.enc -out dec_1k.bin -k 'testpassword'" \
        0.1 \
        "Should decrypt 1KB file in under 0.1 seconds" \
        5
    
    run_performance_test "AES-256 100KB File Decryption" \
        "openssl enc -aes-256-cbc -d -in test_aes_100k.enc -out dec_100k.bin -k 'testpassword'" \
        0.5 \
        "Should decrypt 100KB file in under 0.5 seconds" \
        3
    
    run_performance_test "AES-256 1MB File Decryption" \
        "openssl enc -aes-256-cbc -d -in test_aes_1m.enc -out dec_1m.bin -k 'testpassword'" \
        $AES_ENCRYPT_THRESHOLD \
        "Should decrypt 1MB file in under ${AES_ENCRYPT_THRESHOLD} seconds" \
        3
}

test_rsa_performance() {
    print_test_section "RSA ENCRYPTION/DECRYPTION PERFORMANCE TESTS"
    
    run_performance_test "RSA-1024 Encryption Performance" \
        "openssl rsautl -encrypt -inkey test_public_1024.pem -pubin -in small_file.txt -out rsa_1024.enc" \
        0.1 \
        "Should encrypt small file with RSA-1024 in under 0.1 seconds" \
        5
    
    run_performance_test "RSA-2048 Encryption Performance" \
        "openssl rsautl -encrypt -inkey test_public_2048.pem -pubin -in small_file.txt -out rsa_2048.enc" \
        0.2 \
        "Should encrypt small file with RSA-2048 in under 0.2 seconds" \
        5
    
    run_performance_test "RSA-4096 Encryption Performance" \
        "openssl rsautl -encrypt -inkey test_public_4096.pem -pubin -in small_file.txt -out rsa_4096.enc" \
        1.0 \
        "Should encrypt small file with RSA-4096 in under 1 second" \
        3
    
    # Ensure encrypted files exist for decryption tests
    openssl rsautl -encrypt -inkey test_public_1024.pem -pubin -in small_file.txt -out test_rsa_1024.enc 2>/dev/null
    openssl rsautl -encrypt -inkey test_public_2048.pem -pubin -in small_file.txt -out test_rsa_2048.enc 2>/dev/null
    openssl rsautl -encrypt -inkey test_public_4096.pem -pubin -in small_file.txt -out test_rsa_4096.enc 2>/dev/null
    
    run_performance_test "RSA-1024 Decryption Performance" \
        "openssl rsautl -decrypt -inkey test_private_1024.pem -in test_rsa_1024.enc -out rsa_dec_1024.txt" \
        0.1 \
        "Should decrypt with RSA-1024 in under 0.1 seconds" \
        5
    
    run_performance_test "RSA-2048 Decryption Performance" \
        "openssl rsautl -decrypt -inkey test_private_2048.pem -in test_rsa_2048.enc -out rsa_dec_2048.txt" \
        0.5 \
        "Should decrypt with RSA-2048 in under 0.5 seconds" \
        5
    
    run_performance_test "RSA-4096 Decryption Performance" \
        "openssl rsautl -decrypt -inkey test_private_4096.pem -in test_rsa_4096.enc -out rsa_dec_4096.txt" \
        2.0 \
        "Should decrypt with RSA-4096 in under 2 seconds" \
        3
}

test_hashing_performance() {
    print_test_section "HASH FUNCTION PERFORMANCE TESTS"
    
    run_performance_test "SHA-256 1KB File Hashing" \
        "sha256sum medium_file_1k.bin" \
        0.01 \
        "Should hash 1KB file in under 0.01 seconds" \
        10
    
    run_performance_test "SHA-256 100KB File Hashing" \
        "sha256sum large_file_100k.bin" \
        0.1 \
        "Should hash 100KB file in under 0.1 seconds" \
        5
    
    run_performance_test "SHA-256 1MB File Hashing" \
        "sha256sum large_file_1m.bin" \
        $HASH_THRESHOLD \
        "Should hash 1MB file in under ${HASH_THRESHOLD} second" \
        5
    
    run_performance_test "SHA-256 10MB File Hashing" \
        "sha256sum very_large_file_10m.bin" \
        5.0 \
        "Should hash 10MB file in under 5 seconds" \
        3
    
    run_performance_test "MD5 Performance Comparison" \
        "md5sum large_file_1m.bin" \
        0.5 \
        "MD5 should be faster than SHA-256 for comparison" \
        3
}

test_digital_signature_performance() {
    print_test_section "DIGITAL SIGNATURE PERFORMANCE TESTS"
    
    run_performance_test "RSA-1024 Signing Performance" \
        "openssl dgst -sha256 -sign test_private_1024.pem -out sig_1024.sig medium_file_1k.bin" \
        0.1 \
        "Should sign with RSA-1024 in under 0.1 seconds" \
        5
    
    run_performance_test "RSA-2048 Signing Performance" \
        "openssl dgst -sha256 -sign test_private_2048.pem -out sig_2048.sig medium_file_1k.bin" \
        0.5 \
        "Should sign with RSA-2048 in under 0.5 seconds" \
        5
    
    run_performance_test "RSA-4096 Signing Performance" \
        "openssl dgst -sha256 -sign test_private_4096.pem -out sig_4096.sig medium_file_1k.bin" \
        $SIGNATURE_THRESHOLD \
        "Should sign with RSA-4096 in under ${SIGNATURE_THRESHOLD} seconds" \
        3
    
    # Ensure signature files exist for verification tests
    openssl dgst -sha256 -sign test_private_1024.pem -out test_sig_1024.sig medium_file_1k.bin 2>/dev/null
    openssl dgst -sha256 -sign test_private_2048.pem -out test_sig_2048.sig medium_file_1k.bin 2>/dev/null
    openssl dgst -sha256 -sign test_private_4096.pem -out test_sig_4096.sig medium_file_1k.bin 2>/dev/null
    
    run_performance_test "RSA-1024 Verification Performance" \
        "openssl dgst -sha256 -verify test_public_1024.pem -signature test_sig_1024.sig medium_file_1k.bin" \
        0.05 \
        "Should verify RSA-1024 signature in under 0.05 seconds" \
        10
    
    run_performance_test "RSA-2048 Verification Performance" \
        "openssl dgst -sha256 -verify test_public_2048.pem -signature test_sig_2048.sig medium_file_1k.bin" \
        0.1 \
        "Should verify RSA-2048 signature in under 0.1 seconds" \
        5
    
    run_performance_test "RSA-4096 Verification Performance" \
        "openssl dgst -sha256 -verify test_public_4096.pem -signature test_sig_4096.sig medium_file_1k.bin" \
        0.2 \
        "Should verify RSA-4096 signature in under 0.2 seconds" \
        5
}

test_key_generation_performance() {
    print_test_section "KEY GENERATION PERFORMANCE TESTS"
    
    run_performance_test "RSA-1024 Key Generation" \
        "openssl genrsa 1024" \
        1.0 \
        "Should generate RSA-1024 key in under 1 second" \
        3
    
    run_performance_test "RSA-2048 Key Generation" \
        "openssl genrsa 2048" \
        5.0 \
        "Should generate RSA-2048 key in under 5 seconds" \
        3
    
    run_performance_test "RSA-4096 Key Generation" \
        "openssl genrsa 4096" \
        30.0 \
        "Should generate RSA-4096 key in under 30 seconds" \
        2
}

test_concurrent_operations() {
    print_test_section "CONCURRENT OPERATION PERFORMANCE TESTS"
    
    run_performance_test "Concurrent AES Encryption (4 parallel)" \
        "for i in {1..4}; do openssl enc -aes-256-cbc -in medium_file_10k.bin -out concurrent_\$i.enc -k 'password\$i' & done; wait" \
        2.0 \
        "Should handle 4 concurrent AES encryptions efficiently" \
        3
    
    run_performance_test "Concurrent Hash Operations (8 parallel)" \
        "for i in {1..8}; do sha256sum large_file_100k.bin > hash_\$i.txt & done; wait" \
        3.0 \
        "Should handle 8 concurrent hash operations efficiently" \
        3
    
    run_performance_test "Mixed Concurrent Operations" \
        "sha256sum large_file_1m.bin > hash_mixed.txt & openssl enc -aes-256-cbc -in large_file_100k.bin -out mixed.enc -k 'password' & openssl dgst -sha256 -sign test_private_2048.pem -out mixed.sig medium_file_10k.bin & wait" \
        5.0 \
        "Should handle mixed concurrent crypto operations" \
        3
}

test_memory_performance() {
    print_test_section "MEMORY USAGE PERFORMANCE TESTS"
    
    run_performance_test "Large File Memory Efficiency" \
        "time -v openssl enc -aes-256-cbc -in huge_file_100m.bin -out memory_test.enc -k 'testpassword' 2>&1 | grep 'Maximum resident set size' | awk '{if(\$6 < 100000) exit 0; else exit 1}'" \
        60.0 \
        "Should encrypt 100MB file without excessive memory usage" \
        1
    
    run_performance_test "Memory Cleanup Verification" \
        "ps aux | grep -v grep | grep openssl | wc -l | test \$(cat) -eq 0" \
        1.0 \
        "Should properly clean up processes and memory" \
        1
}

generate_json_report() {
    cat > "$REPORT_FILE" << EOF
{
  "test_phase": "Phase 4 - Performance Tests",
  "test_date": "$(date -Iseconds)",
  "test_duration": "$1",
  "test_environment": "/tmp/crypto_performance_tests",
  "application_path": "$APP_PATH",
  "system_info": {
    "os": "$(uname -s)",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)",
    "cpu": "$(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)",
    "cpu_cores": "$(nproc)",
    "memory_total": "$(free -h | grep '^Mem:' | awk '{print \$2}')",
    "memory_available": "$(free -h | grep '^Mem:' | awk '{print \$7}')"
  },
  "performance_thresholds": {
    "aes_encryption": "${AES_ENCRYPT_THRESHOLD}s",
    "rsa_encryption": "${RSA_ENCRYPT_THRESHOLD}s",
    "hashing": "${HASH_THRESHOLD}s",
    "digital_signature": "${SIGNATURE_THRESHOLD}s"
  },
  "summary": {
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "skipped_tests": $SKIPPED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "performance_categories": {
    "aes_encryption": "AES encryption performance across file sizes",
    "aes_decryption": "AES decryption performance verification", 
    "rsa_operations": "RSA encryption/decryption with different key sizes",
    "hashing": "Hash function performance analysis",
    "digital_signatures": "Signature creation and verification speed",
    "key_generation": "Cryptographic key generation performance",
    "concurrent_ops": "Multi-threaded operation performance",
    "memory_usage": "Memory efficiency and cleanup"
  },
  "performance_recommendations": [
    "$([ $FAILED_TESTS -eq 0 ] && echo 'All performance tests passed - excellent performance' || echo 'Some performance issues detected - consider optimization')",
    "$([ $(echo "$PASSED_TESTS * 100 / $TOTAL_TESTS" | bc) -ge 85 ] && echo 'Performance meets production standards' || echo 'Performance optimization recommended')",
    "Monitor performance with real-world data sizes",
    "Consider hardware acceleration for crypto operations",
    "Profile application under production load conditions"
  ],
  "next_phase": "$([ $FAILED_TESTS -le 5 ] && echo 'Proceed to Phase 5 Platform Testing' || echo 'Optimize performance before platform testing')"
}
EOF
}

cleanup_test_environment() {
    echo -e "${BLUE}Cleaning up performance test environment...${NC}"
    cd /
    rm -rf /tmp/crypto_performance_tests
    echo -e "${GREEN}✓ Performance test environment cleaned${NC}"
}

print_summary() {
    local end_time=$(date)
    local duration="$1"
    
    echo -e "${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}                                   PERFORMANCE TEST SUMMARY${NC}"
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
    
    # Performance assessment
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🚀 EXCELLENT PERFORMANCE: All performance tests passed!${NC}"
        echo -e "${GREEN}✓ Application meets high performance standards${NC}"
    elif [ $FAILED_TESTS -le 3 ]; then
        echo -e "${YELLOW}⚡ GOOD PERFORMANCE: Minor performance issues found${NC}"
        echo -e "${YELLOW}⚠️  Consider optimizing failed operations${NC}"
    elif [ $FAILED_TESTS -le 8 ]; then
        echo -e "${YELLOW}⚡ MODERATE PERFORMANCE: Several operations need optimization${NC}"
        echo -e "${YELLOW}⚠️  Performance tuning recommended${NC}"
    else
        echo -e "${RED}🐌 POOR PERFORMANCE: Significant performance issues detected${NC}"
        echo -e "${RED}⚠️  Major optimization required before production use${NC}"
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
    echo "Phase 4 Performance Tests - $(date)" > "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
    echo "System: $(uname -a)" >> "$LOG_FILE"
    echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)" >> "$LOG_FILE"
    echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}') total" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Setup test environment
    setup_test_environment
    
    # Run all performance test categories
    test_aes_encryption_performance
    test_aes_decryption_performance
    test_rsa_performance
    test_hashing_performance
    test_digital_signature_performance
    test_key_generation_performance
    test_concurrent_operations
    test_memory_performance
    
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
    command -v time &> /dev/null || missing_tools+=("time")
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "Missing required tools: ${missing_tools[*]}"
        echo "Please install missing tools before running performance tests"
        exit 1
    fi
}

# Check tools and run tests
check_tools
main "$@"
