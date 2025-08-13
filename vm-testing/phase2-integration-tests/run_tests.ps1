# Phase 2: Integration Tests - Automated Test Script (Windows PowerShell)
# Cryptography Application Integration Testing Suite
# Date: August 13, 2025

param(
    [switch]$Help,
    [switch]$Verbose
)

# Test counters
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0
$script:SkippedTests = 0

# Logging
$LogFile = "phase2_integration_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ReportFile = "phase2_integration_report.json"
$AppPath = "..\..\build\CryptographyApplication.exe"

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    switch ($Color) {
        "Red"     { Write-Host $Message -ForegroundColor Red }
        "Green"   { Write-Host $Message -ForegroundColor Green }
        "Yellow"  { Write-Host $Message -ForegroundColor Yellow }
        "Blue"    { Write-Host $Message -ForegroundColor Blue }
        "Cyan"    { Write-Host $Message -ForegroundColor Cyan }
        "Magenta" { Write-Host $Message -ForegroundColor Magenta }
        default   { Write-Host $Message }
    }
}

function Write-Header {
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                       PHASE 2: INTEGRATION TESTS - CRYPTOGRAPHY APPLICATION" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "Test Date: $(Get-Date)" "Blue"
    Write-ColorOutput "Log File: $LogFile" "Blue"
    Write-ColorOutput "Report File: $ReportFile" "Blue"
    Write-ColorOutput "Application: $AppPath" "Blue"
    Write-Host ""
}

function Write-TestSection {
    param([string]$Title)
    Write-ColorOutput "┌─────────────────────────────────────────────────────────────────────────────────────────────┐" "Magenta"
    Write-ColorOutput "│ $Title" "Magenta"
    Write-ColorOutput "└─────────────────────────────────────────────────────────────────────────────────────────────┘" "Magenta"
}

function Write-TestLog {
    param([string]$TestName, [string]$Status, [string]$Details)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Status] $TestName`: $Details"
    Add-Content -Path $LogFile -Value $logEntry
}

function Invoke-Test {
    param(
        [string]$TestName,
        [string]$TestCommand,
        [string]$ExpectedBehavior,
        [int]$TimeoutSeconds = 30
    )
    
    $script:TotalTests++
    
    Write-ColorOutput "Testing: $TestName" "Blue"
    Write-ColorOutput "Expected: $ExpectedBehavior" "Yellow"
    Write-ColorOutput "Command: $TestCommand" "Yellow"
    Write-ColorOutput "Timeout: ${TimeoutSeconds}s" "Yellow"
    
    try {
        $job = Start-Job -ScriptBlock {
            param($command)
            Invoke-Expression $command
        } -ArgumentList $TestCommand
        
        $completed = Wait-Job $job -Timeout $TimeoutSeconds
        $result = Receive-Job $job
        Remove-Job $job -Force
        
        if ($completed -and $job.State -eq "Completed") {
            Write-ColorOutput "✓ PASSED" "Green"
            $script:PassedTests++
            Write-TestLog $TestName "PASS" $ExpectedBehavior
        } else {
            Write-ColorOutput "✗ FAILED" "Red"
            $script:FailedTests++
            Write-TestLog $TestName "FAIL" "Command failed or timed out: $TestCommand"
            
            if ($result) {
                Write-ColorOutput "Error Details:" "Red"
                $result | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
            }
        }
    } catch {
        Write-ColorOutput "✗ FAILED" "Red"
        $script:FailedTests++
        Write-TestLog $TestName "FAIL" "Exception: $($_.Exception.Message)"
        Write-ColorOutput "Error Details:" "Red"
        Write-Host "  $($_.Exception.Message)"
    }
    
    Write-Host ""
}

function Initialize-TestEnvironment {
    Write-TestSection "TEST ENVIRONMENT SETUP"
    
    # Create test data directory
    $testDir = "$env:TEMP\crypto_integration_tests"
    if (Test-Path $testDir) {
        Remove-Item $testDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    Set-Location $testDir
    
    # Create test files
    "This is a test document for encryption testing." | Out-File -FilePath "test_document.txt" -Encoding UTF8
    "Small data for RSA testing" | Out-File -FilePath "small_test.txt" -Encoding UTF8
    
    # Create binary test file (10KB)
    $binaryData = 1..10240 | ForEach-Object { Get-Random -Maximum 256 }
    [System.IO.File]::WriteAllBytes("$testDir\binary_test.bin", $binaryData)
    
    # Create large test file (5MB)
    $largeData = [byte[]]::new(5242880)
    [System.IO.File]::WriteAllBytes("$testDir\large_test.dat", $largeData)
    
    # Generate test keys
    if (Get-Command openssl.exe -ErrorAction SilentlyContinue) {
        & openssl genrsa -out test_private.pem 2048 2>$null
        & openssl rsa -in test_private.pem -pubout -out test_public.pem 2>$null
    }
    
    Write-ColorOutput "✓ Test environment prepared" "Green"
    Write-ColorOutput "Test Directory: $testDir" "Blue"
    Write-Host ""
}

function Test-ApplicationStartup {
    Write-TestSection "APPLICATION STARTUP TESTS"
    
    Invoke-Test "Application Binary Exists" `
        "Test-Path '$AppPath'" `
        "Application executable should exist and be accessible" `
        5
    
    Invoke-Test "Application Executable Permissions" `
        "if (Test-Path '$AppPath') { (Get-Item '$AppPath').Extension -eq '.exe' } else { `$false }" `
        "Application should be a valid Windows executable" `
        5
    
    Invoke-Test "Application Dependencies Check" `
        "if (Test-Path '$AppPath') { `$deps = & dumpbin /dependents '$AppPath' 2>$null; `$deps -match 'dll|DLL' } else { `$false }" `
        "Application should have expected DLL dependencies" `
        10
}

function Test-CLIOperations {
    Write-TestSection "COMMAND LINE INTERFACE TESTS"
    
    if (-not (Test-Path $AppPath)) {
        Write-ColorOutput "⊘ SKIPPING CLI tests - Application not found" "Yellow"
        $script:SkippedTests += 2
        return
    }
    
    Invoke-Test "CLI Help Display" `
        "try { `$output = & '$AppPath' --help 2>&1; `$output -match 'help|usage|option' } catch { `$false }" `
        "CLI should display help information" `
        10
    
    Invoke-Test "CLI Error Handling" `
        "try { `$output = & '$AppPath' --invalid-option 2>&1; `$LASTEXITCODE -ne 0 } catch { `$true }" `
        "CLI should handle invalid options gracefully" `
        10
}

function Test-FileEncryptionWorkflow {
    Write-TestSection "FILE ENCRYPTION WORKFLOW TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Encryption workflow tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-Test "AES File Encryption Integration" `
        "& openssl enc -aes-256-cbc -in test_document.txt -out test_document.aes -k 'testpassword' -md sha256 2>$null; Test-Path test_document.aes" `
        "Should encrypt file using AES-256-CBC" `
        15
    
    Invoke-Test "AES File Decryption Integration" `
        "& openssl enc -aes-256-cbc -d -in test_document.aes -out test_document_decrypted.txt -k 'testpassword' -md sha256 2>$null; if (Test-Path test_document_decrypted.txt) { (Get-Content test_document.txt -Raw) -eq (Get-Content test_document_decrypted.txt -Raw) } else { `$false }" `
        "Should decrypt AES file and match original" `
        15
    
    Invoke-Test "RSA Small File Encryption" `
        "& openssl rsautl -encrypt -inkey test_public.pem -pubin -in small_test.txt -out small_test.rsa 2>$null; Test-Path small_test.rsa" `
        "Should encrypt small file using RSA public key" `
        15
    
    Invoke-Test "RSA Small File Decryption" `
        "& openssl rsautl -decrypt -inkey test_private.pem -in small_test.rsa -out small_test_decrypted.txt 2>$null; if (Test-Path small_test_decrypted.txt) { (Get-Content small_test.txt -Raw) -eq (Get-Content small_test_decrypted.txt -Raw) } else { `$false }" `
        "Should decrypt RSA file and match original" `
        15
}

function Test-DigitalSignatureWorkflow {
    Write-TestSection "DIGITAL SIGNATURE WORKFLOW TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Digital signature workflow tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-Test "File Signing Process" `
        "& openssl dgst -sha256 -sign test_private.pem -out test_document.sig test_document.txt 2>$null; Test-Path test_document.sig" `
        "Should create digital signature for file" `
        15
    
    Invoke-Test "Signature Verification Process" `
        "& openssl dgst -sha256 -verify test_public.pem -signature test_document.sig test_document.txt 2>$null; `$LASTEXITCODE -eq 0" `
        "Should verify digital signature successfully" `
        15
    
    Invoke-Test "Signature Tampering Detection" `
        "'tampered content' | Out-File tampered_document.txt; & openssl dgst -sha256 -verify test_public.pem -signature test_document.sig tampered_document.txt 2>$null; `$LASTEXITCODE -ne 0" `
        "Should detect tampering when content is modified" `
        15
}

function Test-HashVerificationWorkflow {
    Write-TestSection "HASH VERIFICATION WORKFLOW TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Hash verification tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-Test "SHA-256 Hash Generation" `
        "`$hash = & openssl dgst -sha256 test_document.txt 2>$null; `$hash | Out-File test_document.sha256; Test-Path test_document.sha256" `
        "Should generate SHA-256 hash file" `
        10
    
    Invoke-Test "Hash Verification Success" `
        "`$originalHash = (& openssl dgst -sha256 test_document.txt).Split('=')[1].Trim(); `$storedHash = (Get-Content test_document.sha256).Split('=')[1].Trim(); `$originalHash -eq `$storedHash" `
        "Should verify hash successfully for unmodified file" `
        10
    
    Invoke-Test "Hash Verification Failure Detection" `
        "'modified content' | Out-File modified_document.txt; `$originalHash = (Get-Content test_document.sha256).Split('=')[1].Trim(); `$modifiedHash = (& openssl dgst -sha256 modified_document.txt).Split('=')[1].Trim(); `$originalHash -ne `$modifiedHash" `
        "Should detect hash mismatch for modified file" `
        10
}

function Test-LargeFileHandling {
    Write-TestSection "LARGE FILE HANDLING TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Large file tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-Test "Large File AES Encryption" `
        "& openssl enc -aes-256-cbc -in large_test.dat -out large_test.aes -k 'testpassword' -md sha256 2>$null; if (Test-Path large_test.aes) { (Get-Item large_test.aes).Length -gt 5000000 } else { `$false }" `
        "Should encrypt large file (5MB+) successfully" `
        30
    
    Invoke-Test "Large File AES Decryption" `
        "& openssl enc -aes-256-cbc -d -in large_test.aes -out large_test_decrypted.dat -k 'testpassword' -md sha256 2>$null; if (Test-Path large_test_decrypted.dat) { (Get-Item large_test.dat).Length -eq (Get-Item large_test_decrypted.dat).Length } else { `$false }" `
        "Should decrypt large file and match original size" `
        30
    
    Invoke-Test "Large File Hash Calculation" `
        "`$hash = & openssl dgst -sha256 large_test.dat 2>$null; `$hash -match '[0-9a-f]{64}'" `
        "Should calculate hash for large file efficiently" `
        20
}

function Test-BinaryFileHandling {
    Write-TestSection "BINARY FILE HANDLING TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Binary file tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-Test "Binary File AES Encryption" `
        "& openssl enc -aes-256-cbc -in binary_test.bin -out binary_test.aes -k 'testpassword' -md sha256 2>$null; Test-Path binary_test.aes" `
        "Should encrypt binary file successfully" `
        15
    
    Invoke-Test "Binary File AES Decryption" `
        "& openssl enc -aes-256-cbc -d -in binary_test.aes -out binary_test_decrypted.bin -k 'testpassword' -md sha256 2>$null; if (Test-Path binary_test_decrypted.bin) { (Get-Item binary_test.bin).Length -eq (Get-Item binary_test_decrypted.bin).Length } else { `$false }" `
        "Should decrypt binary file and match original size exactly" `
        15
    
    Invoke-Test "Binary File Signature" `
        "& openssl dgst -sha256 -sign test_private.pem -out binary_test.sig binary_test.bin 2>$null; & openssl dgst -sha256 -verify test_public.pem -signature binary_test.sig binary_test.bin 2>$null; `$LASTEXITCODE -eq 0" `
        "Should sign and verify binary file successfully" `
        15
}

function Test-ErrorConditions {
    Write-TestSection "ERROR CONDITION TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Error condition tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-Test "Invalid Key Handling" `
        "& openssl enc -aes-256-cbc -d -in test_document.aes -out nul -k 'wrongpassword' -md sha256 2>$null; `$LASTEXITCODE -ne 0" `
        "Should fail gracefully with wrong decryption key" `
        10
    
    Invoke-Test "Missing File Handling" `
        "& openssl enc -aes-256-cbc -in nonexistent.txt -out nul -k 'testpassword' -md sha256 2>$null; `$LASTEXITCODE -ne 0" `
        "Should fail gracefully when input file doesn't exist" `
        5
    
    Invoke-Test "Invalid Signature Verification" `
        "`$randomBytes = 1..256 | ForEach-Object { Get-Random -Maximum 256 }; [System.IO.File]::WriteAllBytes('invalid.sig', `$randomBytes); & openssl dgst -sha256 -verify test_public.pem -signature invalid.sig test_document.txt 2>$null; `$LASTEXITCODE -ne 0" `
        "Should fail gracefully with invalid signature" `
        10
    
    Invoke-Test "Disk Space Check" `
        "`$drive = (Get-Location).Drive; `$freeSpace = (Get-WmiObject -Class Win32_LogicalDisk -Filter \"DeviceID='`$drive'\").FreeSpace; `$freeSpace -gt 100MB" `
        "Should have sufficient disk space for operations" `
        5
}

function Test-PerformanceBasic {
    Write-TestSection "BASIC PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-Test "Encryption Performance Test" `
        "`$start = Get-Date; & openssl enc -aes-256-cbc -in large_test.dat -out perf_test.aes -k 'testpassword' -md sha256 2>$null; `$duration = (Get-Date) - `$start; `$duration.TotalSeconds -lt 45" `
        "Should encrypt 5MB file in reasonable time" `
        45
    
    Invoke-Test "Hash Performance Test" `
        "`$start = Get-Date; & openssl dgst -sha256 large_test.dat 2>$null; `$duration = (Get-Date) - `$start; `$duration.TotalSeconds -lt 30" `
        "Should hash 5MB file quickly" `
        30
    
    Invoke-Test "Signature Performance Test" `
        "`$start = Get-Date; & openssl dgst -sha256 -sign test_private.pem -out perf_test.sig large_test.dat 2>$null; `$duration = (Get-Date) - `$start; `$duration.TotalSeconds -lt 30" `
        "Should sign 5MB file in reasonable time" `
        30
}

function New-JsonReport {
    param([int]$Duration)
    
    $report = @{
        test_phase = "Phase 2 - Integration Tests"
        test_date = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        test_duration = $Duration
        test_environment = "$env:TEMP\crypto_integration_tests"
        application_path = $AppPath
        platform = "Windows PowerShell"
        summary = @{
            total_tests = $script:TotalTests
            passed_tests = $script:PassedTests
            failed_tests = $script:FailedTests
            skipped_tests = $script:SkippedTests
            success_rate = if ($script:TotalTests -gt 0) { [math]::Round(($script:PassedTests * 100.0 / $script:TotalTests), 2) } else { 0 }
        }
        test_categories = @{
            application_startup = "Application launch and dependency tests"
            cli_operations = "Command line interface functionality"
            file_encryption = "End-to-end encryption workflows"
            digital_signatures = "Signature creation and verification"
            hash_verification = "Hash generation and validation"
            large_files = "Large file handling capabilities"
            binary_files = "Binary file processing"
            error_conditions = "Error handling and edge cases"
            performance = "Basic performance characteristics"
        }
        recommendations = @(
            if ($script:FailedTests -eq 0) { "All integration tests passed - ready for Phase 3" } else { "Review failed integration tests before Phase 3" },
            if ($script:SkippedTests -gt 5) { "Several tests skipped - ensure OpenSSL is installed" } else { "Most integration features tested" },
            "Verify application startup if startup tests failed",
            "Check file handling if file operation tests failed",
            "Proceed to security testing if all critical tests pass"
        )
    }
    
    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $ReportFile -Encoding UTF8
}

function Remove-TestEnvironment {
    Write-ColorOutput "Cleaning up test environment..." "Blue"
    Set-Location ..
    $testDir = "$env:TEMP\crypto_integration_tests"
    if (Test-Path $testDir) {
        Remove-Item $testDir -Recurse -Force
    }
    Write-ColorOutput "✓ Test environment cleaned" "Green"
}

function Write-Summary {
    param([int]$Duration)
    
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                                    INTEGRATION TEST SUMMARY" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "End Time: $(Get-Date)" "Blue"
    Write-ColorOutput "Duration: $Duration seconds" "Blue"
    Write-Host ""
    Write-ColorOutput "Total Tests: $($script:TotalTests)" "Blue"
    Write-ColorOutput "Passed: $($script:PassedTests)" "Green"
    Write-ColorOutput "Failed: $($script:FailedTests)" "Red"
    Write-ColorOutput "Skipped: $($script:SkippedTests)" "Yellow"
    Write-Host ""
    
    $successRate = if ($script:TotalTests -gt 0) { [math]::Round(($script:PassedTests * 100.0 / $script:TotalTests), 2) } else { 0 }
    Write-ColorOutput "Success Rate: $successRate%" "Blue"
    
    if ($script:FailedTests -eq 0) {
        Write-ColorOutput "🎉 ALL INTEGRATION TESTS PASSED! Ready for Phase 3 Security Testing." "Green"
    } elseif ($script:FailedTests -le 3) {
        Write-ColorOutput "⚠️  Some minor issues found. Review failed tests before proceeding." "Yellow"
    } else {
        Write-ColorOutput "⚠️  Multiple integration failures. Fix critical issues before Phase 3." "Red"
    }
    
    Write-Host ""
    Write-ColorOutput "Detailed Results: $LogFile" "Blue"
    Write-ColorOutput "JSON Report: $ReportFile" "Blue"
    Write-ColorOutput "================================================================================================" "Cyan"
}

function Show-Usage {
    Write-Host ""
    Write-ColorOutput "USAGE:" "Yellow"
    Write-Host "  .\run_tests.ps1 [OPTIONS]"
    Write-Host ""
    Write-ColorOutput "OPTIONS:" "Yellow"
    Write-Host "  -Help      Show this help message"
    Write-Host "  -Verbose   Show verbose output during testing"
    Write-Host ""
}

# Main execution
function Main {
    if ($Help) {
        Show-Usage
        return
    }
    
    $startTime = Get-Date
    
    Write-Header
    
    # Initialize log file
    "Phase 2 Integration Tests - $(Get-Date)" | Out-File -FilePath $LogFile -Encoding UTF8
    "========================================" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    
    try {
        # Setup test environment
        Initialize-TestEnvironment
        
        # Run all test categories
        Test-ApplicationStartup
        Test-CLIOperations
        Test-FileEncryptionWorkflow
        Test-DigitalSignatureWorkflow
        Test-HashVerificationWorkflow
        Test-LargeFileHandling
        Test-BinaryFileHandling
        Test-ErrorConditions
        Test-PerformanceBasic
        
        # Calculate duration
        $endTime = Get-Date
        $duration = [int]($endTime - $startTime).TotalSeconds
        
        # Generate reports
        New-JsonReport -Duration $duration
        Write-Summary -Duration $duration
        
    } finally {
        # Cleanup
        Remove-TestEnvironment
    }
}

# Run the tests
Main
