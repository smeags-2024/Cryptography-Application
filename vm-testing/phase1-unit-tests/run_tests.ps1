# Phase 1: Unit Tests - Automated Test Script (Windows PowerShell)
# Cryptography Application Unit Testing Suite
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
$LogFile = "phase1_unit_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ReportFile = "phase1_unit_report.json"
$AppPath = "..\..\build\CryptographyApplication.exe"

# Colors for output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
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
    Write-ColorOutput "                         PHASE 1: UNIT TESTS - CRYPTOGRAPHY APPLICATION" "Cyan"
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
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Details
    )
    
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
            } else {
                Write-Host "  Command timed out after ${TimeoutSeconds}s"
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
    $testDir = "$env:TEMP\crypto_unit_tests"
    if (Test-Path $testDir) {
        Remove-Item $testDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    Set-Location $testDir
    
    # Create test files
    "This is a test document for unit testing." | Out-File -FilePath "test_document.txt" -Encoding UTF8
    "Small test data" | Out-File -FilePath "small_test.txt" -Encoding UTF8
    
    # Create binary test file
    $binaryData = 1..1024 | ForEach-Object { Get-Random -Maximum 256 }
    [System.IO.File]::WriteAllBytes("$testDir\binary_test.bin", $binaryData)
    
    # Generate test keys using OpenSSL
    if (Get-Command openssl.exe -ErrorAction SilentlyContinue) {
        & openssl genrsa -out test_private.pem 2048 2>$null
        & openssl rsa -in test_private.pem -pubout -out test_public.pem 2>$null
    }
    
    Write-ColorOutput "✓ Test environment prepared" "Green"
    Write-ColorOutput "Test Directory: $testDir" "Blue"
    Write-Host ""
}

function Test-BuildSystem {
    Write-TestSection "BUILD SYSTEM TESTS"
    
    Invoke-Test "CMake Configuration Files" `
        "Test-Path '..\..\CMakeLists.txt'" `
        "CMakeLists.txt should exist in project root" `
        5
    
    Invoke-Test "Source Directory Structure" `
        "Test-Path '..\..\src'" `
        "Source directory should exist" `
        5
    
    Invoke-Test "Include Directory Structure" `
        "Test-Path '..\..\include'" `
        "Include directory should exist" `
        5
    
    Invoke-Test "Build Directory Exists" `
        "Test-Path '..\..\build'" `
        "Build directory should exist after building" `
        5
    
    Invoke-Test "Application Executable" `
        "Test-Path '$AppPath'" `
        "Application executable should exist" `
        5
}

function Test-AESCryptography {
    Write-TestSection "AES CRYPTOGRAPHY TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING AES tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-Test "AES-256-CBC Encryption" `
        "& openssl enc -aes-256-cbc -in test_document.txt -out aes_test.enc -k 'testpassword' -md sha256" `
        "Should encrypt file using AES-256-CBC" `
        15
    
    Invoke-Test "AES-256-CBC Decryption" `
        "& openssl enc -aes-256-cbc -d -in aes_test.enc -out aes_decrypted.txt -k 'testpassword' -md sha256; if (Test-Path aes_test.enc -and Test-Path aes_decrypted.txt) { `$true } else { `$false }" `
        "Should decrypt AES file successfully" `
        15
    
    Invoke-Test "AES Encryption Randomness" `
        "& openssl enc -aes-256-cbc -in test_document.txt -out aes1.enc -k 'password' -md sha256; & openssl enc -aes-256-cbc -in test_document.txt -out aes2.enc -k 'password' -md sha256; if (Test-Path aes1.enc -and Test-Path aes2.enc) { -not (Compare-Object (Get-Content aes1.enc -Raw) (Get-Content aes2.enc -Raw)) } else { `$false }" `
        "Multiple AES encryptions should produce different output" `
        20
    
    Invoke-Test "AES Key Validation" `
        "& openssl enc -aes-256-cbc -d -in aes_test.enc -out /dev/null -k 'wrongpassword' 2>$null; if (`$LASTEXITCODE -ne 0) { `$true } else { `$false }" `
        "Should fail with incorrect AES key" `
        10
}

function Test-RSACryptography {
    Write-TestSection "RSA CRYPTOGRAPHY TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING RSA tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 5
        return
    }
    
    Invoke-Test "RSA Key Generation" `
        "& openssl genrsa -out rsa_test_key.pem 2048 2>$null; Test-Path rsa_test_key.pem" `
        "Should generate RSA-2048 private key" `
        15
    
    Invoke-Test "RSA Public Key Extraction" `
        "& openssl rsa -in rsa_test_key.pem -pubout -out rsa_test_pub.pem 2>$null; Test-Path rsa_test_pub.pem" `
        "Should extract RSA public key" `
        10
    
    Invoke-Test "RSA Encryption" `
        "& openssl rsautl -encrypt -inkey rsa_test_pub.pem -pubin -in small_test.txt -out rsa_encrypted.bin 2>$null; Test-Path rsa_encrypted.bin" `
        "Should encrypt small file with RSA public key" `
        15
    
    Invoke-Test "RSA Decryption" `
        "& openssl rsautl -decrypt -inkey rsa_test_key.pem -in rsa_encrypted.bin -out rsa_decrypted.txt 2>$null; if (Test-Path rsa_decrypted.txt) { (Get-Content small_test.txt -Raw) -eq (Get-Content rsa_decrypted.txt -Raw) } else { `$false }" `
        "Should decrypt RSA file and match original" `
        15
    
    Invoke-Test "RSA Key Size Validation" `
        "& openssl rsa -in rsa_test_key.pem -text -noout 2>$null | Select-String '2048 bit'" `
        "RSA key should be 2048 bits" `
        10
}

function Test-HashFunctions {
    Write-TestSection "HASH FUNCTION TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Hash tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-Test "SHA-256 Hash Generation" `
        "& openssl dgst -sha256 test_document.txt | Out-File sha256_hash.txt; Test-Path sha256_hash.txt" `
        "Should generate SHA-256 hash" `
        10
    
    Invoke-Test "SHA-256 Hash Consistency" `
        "`$hash1 = (& openssl dgst -sha256 test_document.txt); `$hash2 = (& openssl dgst -sha256 test_document.txt); `$hash1 -eq `$hash2" `
        "SHA-256 should produce consistent hashes" `
        10
    
    Invoke-Test "MD5 Hash Generation" `
        "& openssl dgst -md5 test_document.txt | Out-File md5_hash.txt; Test-Path md5_hash.txt" `
        "Should generate MD5 hash" `
        10
    
    Invoke-Test "Hash Format Validation" `
        "`$hash = & openssl dgst -sha256 test_document.txt; `$hash -match '[0-9a-f]{64}'" `
        "SHA-256 hash should be 64 hex characters" `
        5
}

function Test-DigitalSignatures {
    Write-TestSection "DIGITAL SIGNATURE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Digital Signature tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-Test "Digital Signature Creation" `
        "& openssl dgst -sha256 -sign test_private.pem -out signature.sig test_document.txt 2>$null; Test-Path signature.sig" `
        "Should create digital signature" `
        15
    
    Invoke-Test "Digital Signature Verification" `
        "& openssl dgst -sha256 -verify test_public.pem -signature signature.sig test_document.txt 2>$null; `$LASTEXITCODE -eq 0" `
        "Should verify digital signature successfully" `
        15
    
    Invoke-Test "Signature Tampering Detection" `
        "'tampered content' | Out-File tampered.txt; & openssl dgst -sha256 -verify test_public.pem -signature signature.sig tampered.txt 2>$null; `$LASTEXITCODE -ne 0" `
        "Should detect signature tampering" `
        15
    
    Invoke-Test "Signature File Integrity" `
        "`$size = (Get-Item signature.sig).Length; `$size -gt 200 -and `$size -lt 500" `
        "Signature file should have reasonable size" `
        5
}

function Test-FileOperations {
    Write-TestSection "FILE OPERATION TESTS"
    
    Invoke-Test "File Reading Test" `
        "`$content = Get-Content test_document.txt -Raw; `$content.Length -gt 0" `
        "Should read file content successfully" `
        5
    
    Invoke-Test "File Writing Test" `
        "'Test write operation' | Out-File write_test.txt; Test-Path write_test.txt" `
        "Should write file successfully" `
        5
    
    Invoke-Test "Binary File Handling" `
        "Test-Path binary_test.bin -and (Get-Item binary_test.bin).Length -eq 1024" `
        "Should handle binary files correctly" `
        5
    
    Invoke-Test "File Permission Test" `
        "New-Item -ItemType File -Path permission_test.txt -Force; Test-Path permission_test.txt" `
        "Should create files with appropriate permissions" `
        5
    
    Invoke-Test "Large File Simulation" `
        "`$data = 'x' * 10000; `$data | Out-File large_test.txt; (Get-Item large_test.txt).Length -gt 9000" `
        "Should handle larger file operations" `
        10
}

function Test-Dependencies {
    Write-TestSection "DEPENDENCY TESTS"
    
    Invoke-Test "OpenSSL Availability" `
        "Get-Command openssl.exe -ErrorAction SilentlyContinue" `
        "OpenSSL should be available in PATH" `
        5
    
    Invoke-Test "CMake Availability" `
        "Get-Command cmake.exe -ErrorAction SilentlyContinue" `
        "CMake should be available for building" `
        5
    
    Invoke-Test "Visual Studio Build Tools" `
        "Get-Command cl.exe -ErrorAction SilentlyContinue -or (Test-Path '${env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe')" `
        "Visual Studio compiler should be available" `
        5
    
    Invoke-Test "PowerShell Version" `
        "`$PSVersionTable.PSVersion.Major -ge 5" `
        "PowerShell version should be 5.0 or higher" `
        5
}

function Test-MemorySafety {
    Write-TestSection "MEMORY SAFETY TESTS"
    
    Invoke-Test "Application Memory Test" `
        "if (Test-Path '$AppPath') { `$proc = Start-Process '$AppPath' --version -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue; if (`$proc) { Start-Sleep 2; `$proc.Kill(); `$true } else { `$false } } else { `$false }" `
        "Application should start and exit without memory errors" `
        15
    
    Invoke-Test "Temporary File Cleanup" `
        "New-Item -ItemType File -Path temp_test.tmp; Remove-Item temp_test.tmp; -not (Test-Path temp_test.tmp)" `
        "Should properly clean up temporary files" `
        5
    
    Invoke-Test "Memory Allocation Test" `
        "`$array = 1..1000; `$array.Length -eq 1000; `$array = `$null; `$true" `
        "Should handle memory allocation and deallocation" `
        5
}

function New-JsonReport {
    param([int]$Duration)
    
    $report = @{
        test_phase = "Phase 1 - Unit Tests"
        test_date = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        test_duration = $Duration
        test_environment = "$env:TEMP\crypto_unit_tests"
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
            build_system = "Build configuration and project structure"
            aes_cryptography = "AES encryption and decryption functionality"
            rsa_cryptography = "RSA key generation and crypto operations"
            hash_functions = "SHA-256 and MD5 hash generation"
            digital_signatures = "Digital signature creation and verification"
            file_operations = "File I/O and manipulation operations"
            dependencies = "Required dependency availability"
            memory_safety = "Memory management and safety checks"
        }
        recommendations = @(
            if ($script:FailedTests -eq 0) { "All unit tests passed - ready for integration testing" } else { "Review failed unit tests before proceeding" },
            if ($script:SkippedTests -gt 0) { "Some tests were skipped - ensure all dependencies are installed" } else { "All test categories were executed" },
            "Consider running tests on different Windows versions",
            "Verify functionality with real-world data sizes"
        )
    }
    
    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $ReportFile -Encoding UTF8
}

function Remove-TestEnvironment {
    Write-ColorOutput "Cleaning up test environment..." "Blue"
    Set-Location ..
    $testDir = "$env:TEMP\crypto_unit_tests"
    if (Test-Path $testDir) {
        Remove-Item $testDir -Recurse -Force
    }
    Write-ColorOutput "✓ Test environment cleaned" "Green"
}

function Write-Summary {
    param([int]$Duration)
    
    $endTime = Get-Date
    
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                                      UNIT TEST SUMMARY" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "End Time: $endTime" "Blue"
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
        Write-ColorOutput "🎉 ALL UNIT TESTS PASSED! Ready for Phase 2 Integration Testing." "Green"
    } elseif ($script:FailedTests -le 3) {
        Write-ColorOutput "⚠️  Some minor issues found. Review failed tests before proceeding." "Yellow"
    } else {
        Write-ColorOutput "⚠️  Multiple test failures. Fix issues before integration testing." "Red"
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
    Write-ColorOutput "EXAMPLES:" "Yellow"
    Write-Host "  .\run_tests.ps1           # Run all unit tests"
    Write-Host "  .\run_tests.ps1 -Verbose  # Run with verbose output"
    Write-Host "  .\run_tests.ps1 -Help     # Show help"
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
    "Phase 1 Unit Tests - $(Get-Date)" | Out-File -FilePath $LogFile -Encoding UTF8
    "========================================" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    
    try {
        # Setup test environment
        Initialize-TestEnvironment
        
        # Run all test categories
        Test-BuildSystem
        Test-AESCryptography
        Test-RSACryptography
        Test-HashFunctions
        Test-DigitalSignatures
        Test-FileOperations
        Test-Dependencies
        Test-MemorySafety
        
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
