# VM Testing Framework - Test Automation Scripts

This directory contains automated test scripts for each phase of the VM testing framework. These scripts are designed to make testing quicker and easier by providing structured output that's easy to read for diagnosing issues.

## Overview

The testing framework consists of 5 phases, each with its own automated test script:

### Phase 1: Unit Tests (`phase1-unit-tests/`)
- **Script:** `run_tests.sh`
- **Purpose:** Comprehensive unit testing of all application components
- **Coverage:** Build system, crypto modules, file operations, dependencies, memory safety
- **Output:** Colored console output, detailed logs, JSON reports

### Phase 2: Integration Tests (`phase2-integration-tests/`)
- **Script:** `run_tests.sh`
- **Purpose:** End-to-end workflow testing and component integration
- **Coverage:** File encryption workflows, signature workflows, error handling, performance basics
- **Output:** Test summaries with performance data and workflow validation

### Phase 3: Security Tests (`phase3-security-tests/`)
- **Script:** `run_tests.sh`
- **Purpose:** Security vulnerability assessment and cryptographic strength validation
- **Coverage:** Key strength, password security, side-channel resistance, crypto vulnerabilities
- **Output:** Security level assessment with detailed vulnerability analysis

### Phase 4: Performance Tests (`phase4-performance-tests/`)
- **Script:** `run_tests.sh`
- **Purpose:** Performance benchmarking and optimization validation
- **Coverage:** Encryption/decryption speed, memory usage, concurrent operations, scalability
- **Output:** Performance metrics with timing data and threshold compliance

### Phase 5: Platform Tests (`phase5-platform-tests/`)
- **Script:** `run_tests.sh`
- **Purpose:** Cross-platform compatibility and deployment readiness
- **Coverage:** OS compatibility, library dependencies, filesystem support, environment variables
- **Output:** Platform compatibility assessment with deployment readiness status

## Features

### Consistent Output Format
- **Colored Output:** Green for passed tests, red for failures, yellow for warnings, blue for information
- **Progress Tracking:** Real-time test progress with counters and status indicators
- **Structured Sections:** Clear separation of test categories with visual headers

### Comprehensive Logging
- **Timestamped Logs:** All test results logged with timestamps for tracking
- **Error Details:** Detailed error messages and command output for failed tests
- **Performance Data:** Timing information and performance metrics captured

### JSON Reporting
- **Machine-Readable:** JSON reports for automated analysis and CI/CD integration
- **Summary Statistics:** Test counts, success rates, and overall assessments
- **Recommendations:** Actionable recommendations based on test results

### Diagnostic-Friendly Design
- **Easy Issue Identification:** Clear failure messages with context
- **Command Transparency:** Shows exact commands being executed
- **Error Context:** Captures and displays relevant error information
- **Timeout Handling:** Prevents hanging tests with configurable timeouts

## Usage

### Running Individual Phase Tests
```bash
# Navigate to specific phase directory
cd phase1-unit-tests/
./run_tests.sh

# Or run from vm-testing directory
./phase1-unit-tests/run_tests.sh
```

### Running All Tests Sequentially
```bash
# Run all phases in order
for phase in phase{1..5}-*/; do
    echo "Starting $phase"
    ./$phase/run_tests.sh
    echo "Completed $phase"
done
```

### Automated Test Execution
```bash
# Example automated testing script
#!/bin/bash
PHASES=("phase1-unit-tests" "phase2-integration-tests" "phase3-security-tests" "phase4-performance-tests" "phase5-platform-tests")

for phase in "${PHASES[@]}"; do
    echo "=== Running $phase ==="
    cd "$phase" && ./run_tests.sh
    if [ $? -ne 0 ]; then
        echo "Phase $phase failed, stopping execution"
        exit 1
    fi
    cd ..
done
```

### Phase 4: Performance Tests (`phase4-performance-tests/`)
**Duration:** 2-3 days  
**Focus:** Performance and scalability  
**VMs Required:** 2-3 (Varied specs)  

**Test Categories:**
- Encryption/decryption benchmarks
- Large file handling
- Memory usage profiling
- CPU utilization testing
- Scalability assessment

### Phase 5: Platform Tests (`phase5-platform-tests/`)
**Duration:** 3-4 days  
**Focus:** Cross-platform compatibility  
**VMs Required:** 5-6 (Different OS)  

**Test Categories:**
- Ubuntu 20.04/22.04 LTS
- CentOS/RHEL 8/9
- Windows 10/11
- macOS (if available)
- Different architecture testing

---

## 🖥️ VM Configuration Requirements

### Minimum VM Specifications:
- **CPU:** 2 cores, 2.0GHz+
- **RAM:** 4GB minimum, 8GB recommended
- **Storage:** 20GB available space
- **Network:** Internet access for dependency installation

### Recommended VM Specifications:
- **CPU:** 4 cores, 2.5GHz+
- **RAM:** 8GB minimum, 16GB recommended
- **Storage:** 50GB available space
- **GPU:** Hardware acceleration (optional, for performance tests)

---

## 📋 Test Data Management

### Test Files (`test-data/`)
- Sample documents (various sizes)
- Binary files for testing
- Large files for performance testing
- Corrupted files for error handling
- Reference cryptographic vectors

### VM Snapshots
- Clean base installations
- Pre-configured development environments
- Checkpoint states for rollback

---

## 🔧 Testing Tools & Dependencies

### Required Tools:
- **Build Tools:** GCC/Clang, CMake, Make
- **Testing Frameworks:** Google Test, Qt Test Framework
- **Profiling Tools:** Valgrind, GDB, Performance analyzers
- **Security Tools:** Static analysis tools, Memory checkers

### Platform-Specific Dependencies:
- **Linux:** build-essential, cmake, qt5-dev, openssl-dev
- **Windows:** Visual Studio, Qt5, OpenSSL binaries
- **macOS:** Xcode, Homebrew, Qt5, OpenSSL

---

## 📊 Test Metrics & Reporting

### Success Criteria:
- **Unit Tests:** 95%+ pass rate
- **Integration Tests:** 90%+ pass rate
- **Security Tests:** Zero critical vulnerabilities
- **Performance Tests:** Meet defined benchmarks
- **Platform Tests:** 100% compatibility

### Reporting Format:
- Automated test reports (JUnit XML)
- Performance benchmark results
- Security vulnerability reports
- Platform compatibility matrix
- Final consolidation report

---

## 🚀 Getting Started

1. **Setup VM Environment:**
   ```bash
   # Navigate to vm-testing directory
   cd vm-testing
   
   # Review testing requirements and setup
   cat README.md
   ```

2. **Prepare Test Data:**
   ```bash
   # Generate test data
   cd test-data
   ./generate_test_data.sh
   ```

3. **Run Test Phase:**
   ```bash
   # Example: Run Phase 1 tests
   cd phase1-unit-tests
   ./run_unit_tests.sh
   ```

---

## 📝 Test Execution Log

### Phase 1 Status: ⏳ PENDING
- [ ] VM Setup Complete
- [ ] Dependencies Installed
- [ ] Test Data Generated
- [ ] Unit Tests Executed
- [ ] Results Documented

### Phase 2 Status: ⏳ PENDING
- [ ] Integration Environment Ready
- [ ] Cross-component Testing
- [ ] GUI Testing Complete
- [ ] Error Scenarios Tested
- [ ] Results Documented

### Phase 3 Status: ⏳ PENDING
- [ ] Security Environment Isolated
- [ ] Vulnerability Scans Complete
- [ ] Penetration Testing Done
- [ ] Security Report Generated
- [ ] Mitigations Implemented

### Phase 4 Status: ⏳ PENDING
- [ ] Performance Environment Setup
- [ ] Benchmark Tests Complete
- [ ] Scalability Tests Done
- [ ] Performance Report Generated
- [ ] Optimization Recommendations

### Phase 5 Status: ⏳ PENDING
- [ ] Multi-platform VMs Ready
- [ ] Platform-specific Testing
- [ ] Compatibility Matrix Complete
- [ ] Platform Issues Resolved
- [ ] Final Compatibility Report

---

**Last Updated:** August 13, 2025  
**Next Update:** August 14, 2025
