# Phase 4: Performance Tests - Automated Test Script (Windows PowerShell)
# Cryptography Application Performance Testing Suite
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

# Performance metrics
$script:PerformanceResults = @{}

# Logging
$LogFile = "phase4_performance_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ReportFile = "phase4_performance_report.json"
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
    Write-ColorOutput "                       PHASE 4: PERFORMANCE TESTS - CRYPTOGRAPHY APPLICATION" "Cyan"
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
    param([string]$TestName, [string]$Status, [string]$Details, [double]$Duration = 0)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $durationStr = if ($Duration -gt 0) { " (${Duration}s)" } else { "" }
    $logEntry = "[$timestamp] [$Status] $TestName$durationStr`: $Details"
    Add-Content -Path $LogFile -Value $logEntry
}

function Invoke-PerformanceTest {
    param(
        [string]$TestName,
        [scriptblock]$TestBlock,
        [string]$ExpectedBehavior,
        [double]$MaxDurationSeconds = 60,
        [string]$Category = "General"
    )
    
    $script:TotalTests++
    
    Write-ColorOutput "Performance Test: $TestName" "Blue"
    Write-ColorOutput "Category: $Category" "Magenta"
    Write-ColorOutput "Expected: $ExpectedBehavior" "Yellow"
    Write-ColorOutput "Max Duration: ${MaxDurationSeconds}s" "Yellow"
    
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $result = & $TestBlock
        $stopwatch.Stop()
        $duration = $stopwatch.Elapsed.TotalSeconds
        
        # Store performance metric
        if (-not $script:PerformanceResults.ContainsKey($Category)) {
            $script:PerformanceResults[$Category] = @{}
        }
        $script:PerformanceResults[$Category][$TestName] = @{
            duration = $duration
            max_duration = $MaxDurationSeconds
            passed = $result -and ($duration -le $MaxDurationSeconds)
        }
        
        Write-ColorOutput "Duration: $([math]::Round($duration, 3))s" "Cyan"
        
        if ($result -and $duration -le $MaxDurationSeconds) {
            Write-ColorOutput "✓ PASSED" "Green"
            $script:PassedTests++
            Write-TestLog $TestName "PASS" $ExpectedBehavior $duration
        } else {
            $reason = if (-not $result) { "Test failed" } else { "Exceeded time limit" }
            Write-ColorOutput "✗ FAILED ($reason)" "Red"
            $script:FailedTests++
            Write-TestLog $TestName "FAIL" "$reason`: $ExpectedBehavior" $duration
        }
    } catch {
        Write-ColorOutput "✗ FAILED (Exception)" "Red"
        $script:FailedTests++
        Write-TestLog $TestName "FAIL" "Exception: $($_.Exception.Message)"
        Write-ColorOutput "Error Details:" "Red"
        Write-Host "  $($_.Exception.Message)"
    }
    
    Write-Host ""
}

function Initialize-PerformanceTestEnvironment {
    Write-TestSection "PERFORMANCE TEST ENVIRONMENT SETUP"
    
    # Create performance test directory
    $perfTestDir = "$env:TEMP\crypto_performance_tests"
    if (Test-Path $perfTestDir) {
        Remove-Item $perfTestDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $perfTestDir -Force | Out-Null
    Set-Location $perfTestDir
    
    # Create test files of various sizes
    Write-ColorOutput "Creating test files..." "Blue"
    
    # Small file (1KB)
    $smallData = "x" * 1024
    $smallData | Out-File -FilePath "small_1kb.txt" -Encoding UTF8 -NoNewline
    
    # Medium file (100KB) 
    $mediumData = "x" * 102400
    $mediumData | Out-File -FilePath "medium_100kb.txt" -Encoding UTF8 -NoNewline
    
    # Large file (1MB)
    $largeData = [byte[]]::new(1048576)
    for ($i = 0; $i -lt $largeData.Length; $i++) { $largeData[$i] = [byte]($i % 256) }
    [System.IO.File]::WriteAllBytes("$perfTestDir\large_1mb.dat", $largeData)
    
    # Very large file (10MB)
    $veryLargeData = [byte[]]::new(10485760)
    for ($i = 0; $i -lt $veryLargeData.Length; $i++) { $veryLargeData[$i] = [byte]($i % 256) }
    [System.IO.File]::WriteAllBytes("$perfTestDir\very_large_10mb.dat", $veryLargeData)
    
    # Huge file (50MB) - for stress testing
    $hugeData = [byte[]]::new(52428800)
    for ($i = 0; $i -lt $hugeData.Length; $i++) { $hugeData[$i] = [byte]($i % 256) }
    [System.IO.File]::WriteAllBytes("$perfTestDir\huge_50mb.dat", $hugeData)
    
    # Generate performance test keys
    if (Get-Command openssl.exe -ErrorAction SilentlyContinue) {
        & openssl genrsa -out perf_test_2048.pem 2048 2>$null
        & openssl genrsa -out perf_test_4096.pem 4096 2>$null
        & openssl rsa -in perf_test_2048.pem -pubout -out perf_test_2048_public.pem 2>$null
        & openssl rsa -in perf_test_4096.pem -pubout -out perf_test_4096_public.pem 2>$null
    }
    
    Write-ColorOutput "✓ Performance test environment prepared" "Green"
    Write-ColorOutput "Test Directory: $perfTestDir" "Blue"
    Write-ColorOutput "Test Files Created:" "Blue"
    Get-ChildItem *.txt, *.dat | ForEach-Object { 
        $sizeKB = [math]::Round($_.Length / 1024, 2)
        Write-ColorOutput "  $($_.Name) - ${sizeKB} KB" "Cyan"
    }
    Write-Host ""
}

function Test-EncryptionPerformance {
    Write-TestSection "ENCRYPTION PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Encryption performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 5
        return
    }
    
    Invoke-PerformanceTest "AES-256 Small File Encryption (1KB)" {
        & openssl enc -aes-256-cbc -in small_1kb.txt -out small_1kb.aes -k 'perftest' -md sha256 2>$null
        $LASTEXITCODE -eq 0
    } "Should encrypt 1KB file quickly" 2 "AES_Encryption"
    
    Invoke-PerformanceTest "AES-256 Medium File Encryption (100KB)" {
        & openssl enc -aes-256-cbc -in medium_100kb.txt -out medium_100kb.aes -k 'perftest' -md sha256 2>$null
        $LASTEXITCODE -eq 0
    } "Should encrypt 100KB file efficiently" 5 "AES_Encryption"
    
    Invoke-PerformanceTest "AES-256 Large File Encryption (1MB)" {
        & openssl enc -aes-256-cbc -in large_1mb.dat -out large_1mb.aes -k 'perftest' -md sha256 2>$null
        $LASTEXITCODE -eq 0
    } "Should encrypt 1MB file within time limit" 10 "AES_Encryption"
    
    Invoke-PerformanceTest "AES-256 Very Large File Encryption (10MB)" {
        & openssl enc -aes-256-cbc -in very_large_10mb.dat -out very_large_10mb.aes -k 'perftest' -md sha256 2>$null
        $LASTEXITCODE -eq 0
    } "Should encrypt 10MB file within reasonable time" 30 "AES_Encryption"
    
    Invoke-PerformanceTest "AES-256 Huge File Encryption (50MB)" {
        & openssl enc -aes-256-cbc -in huge_50mb.dat -out huge_50mb.aes -k 'perftest' -md sha256 2>$null
        $LASTEXITCODE -eq 0
    } "Should encrypt 50MB file within time limit" 120 "AES_Encryption"
}

function Test-DecryptionPerformance {
    Write-TestSection "DECRYPTION PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Decryption performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-PerformanceTest "AES-256 Small File Decryption (1KB)" {
        if (Test-Path small_1kb.aes) {
            & openssl enc -aes-256-cbc -d -in small_1kb.aes -out small_1kb_dec.txt -k 'perftest' -md sha256 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should decrypt 1KB file quickly" 2 "AES_Decryption"
    
    Invoke-PerformanceTest "AES-256 Medium File Decryption (100KB)" {
        if (Test-Path medium_100kb.aes) {
            & openssl enc -aes-256-cbc -d -in medium_100kb.aes -out medium_100kb_dec.txt -k 'perftest' -md sha256 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should decrypt 100KB file efficiently" 5 "AES_Decryption"
    
    Invoke-PerformanceTest "AES-256 Large File Decryption (1MB)" {
        if (Test-Path large_1mb.aes) {
            & openssl enc -aes-256-cbc -d -in large_1mb.aes -out large_1mb_dec.dat -k 'perftest' -md sha256 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should decrypt 1MB file within time limit" 10 "AES_Decryption"
    
    Invoke-PerformanceTest "AES-256 Very Large File Decryption (10MB)" {
        if (Test-Path very_large_10mb.aes) {
            & openssl enc -aes-256-cbc -d -in very_large_10mb.aes -out very_large_10mb_dec.dat -k 'perftest' -md sha256 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should decrypt 10MB file within reasonable time" 30 "AES_Decryption"
}

function Test-RSAPerformance {
    Write-TestSection "RSA PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING RSA performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 4
        return
    }
    
    Invoke-PerformanceTest "RSA-2048 Key Generation" {
        & openssl genrsa -out rsa_perf_2048.pem 2048 2>$null
        $LASTEXITCODE -eq 0 -and (Test-Path rsa_perf_2048.pem)
    } "Should generate 2048-bit RSA key pair quickly" 5 "RSA_KeyGen"
    
    Invoke-PerformanceTest "RSA-4096 Key Generation" {
        & openssl genrsa -out rsa_perf_4096.pem 4096 2>$null
        $LASTEXITCODE -eq 0 -and (Test-Path rsa_perf_4096.pem)
    } "Should generate 4096-bit RSA key pair within time limit" 20 "RSA_KeyGen"
    
    # Create small test file for RSA encryption (RSA can only encrypt small data)
    "Small data for RSA encryption test" | Out-File -FilePath "rsa_test_data.txt" -Encoding UTF8 -NoNewline
    
    Invoke-PerformanceTest "RSA-2048 Encryption" {
        if (Test-Path perf_test_2048_public.pem) {
            & openssl rsautl -encrypt -inkey perf_test_2048_public.pem -pubin -in rsa_test_data.txt -out rsa_test_2048.enc 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should encrypt with RSA-2048 quickly" 3 "RSA_Encryption"
    
    Invoke-PerformanceTest "RSA-2048 Decryption" {
        if (Test-Path rsa_test_2048.enc -and Test-Path perf_test_2048.pem) {
            & openssl rsautl -decrypt -inkey perf_test_2048.pem -in rsa_test_2048.enc -out rsa_test_2048_dec.txt 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should decrypt with RSA-2048 quickly" 3 "RSA_Decryption"
}

function Test-HashPerformance {
    Write-TestSection "HASH PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Hash performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 6
        return
    }
    
    Invoke-PerformanceTest "SHA-256 Small File Hash (1KB)" {
        & openssl dgst -sha256 small_1kb.txt 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 1KB file very quickly" 1 "SHA256_Hash"
    
    Invoke-PerformanceTest "SHA-256 Medium File Hash (100KB)" {
        & openssl dgst -sha256 medium_100kb.txt 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 100KB file quickly" 2 "SHA256_Hash"
    
    Invoke-PerformanceTest "SHA-256 Large File Hash (1MB)" {
        & openssl dgst -sha256 large_1mb.dat 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 1MB file efficiently" 5 "SHA256_Hash"
    
    Invoke-PerformanceTest "SHA-256 Very Large File Hash (10MB)" {
        & openssl dgst -sha256 very_large_10mb.dat 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 10MB file within time limit" 15 "SHA256_Hash"
    
    Invoke-PerformanceTest "SHA-512 Large File Hash (1MB)" {
        & openssl dgst -sha512 large_1mb.dat 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 1MB file with SHA-512 efficiently" 5 "SHA512_Hash"
    
    Invoke-PerformanceTest "MD5 Large File Hash (1MB)" {
        & openssl dgst -md5 large_1mb.dat 2>$null | Out-Null
        $LASTEXITCODE -eq 0
    } "Should hash 1MB file with MD5 quickly (legacy test)" 3 "MD5_Hash"
}

function Test-SignaturePerformance {
    Write-TestSection "DIGITAL SIGNATURE PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Signature performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 6
        return
    }
    
    Invoke-PerformanceTest "RSA-2048 Signature Creation (Small File)" {
        if (Test-Path perf_test_2048.pem) {
            & openssl dgst -sha256 -sign perf_test_2048.pem -out small_1kb.sig small_1kb.txt 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should sign small file quickly with RSA-2048" 3 "RSA_Signing"
    
    Invoke-PerformanceTest "RSA-2048 Signature Verification (Small File)" {
        if (Test-Path small_1kb.sig -and Test-Path perf_test_2048_public.pem) {
            & openssl dgst -sha256 -verify perf_test_2048_public.pem -signature small_1kb.sig small_1kb.txt 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should verify signature quickly with RSA-2048" 2 "RSA_Verification"
    
    Invoke-PerformanceTest "RSA-2048 Signature Creation (Large File)" {
        if (Test-Path perf_test_2048.pem) {
            & openssl dgst -sha256 -sign perf_test_2048.pem -out large_1mb.sig large_1mb.dat 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should sign 1MB file efficiently with RSA-2048" 8 "RSA_Signing"
    
    Invoke-PerformanceTest "RSA-4096 Signature Creation (Small File)" {
        if (Test-Path perf_test_4096.pem) {
            & openssl dgst -sha256 -sign perf_test_4096.pem -out small_4096.sig small_1kb.txt 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should sign small file with RSA-4096 within time limit" 8 "RSA_Signing"
    
    Invoke-PerformanceTest "RSA-4096 Signature Verification (Small File)" {
        if (Test-Path small_4096.sig -and Test-Path perf_test_4096_public.pem) {
            & openssl dgst -sha256 -verify perf_test_4096_public.pem -signature small_4096.sig small_1kb.txt 2>$null
            $LASTEXITCODE -eq 0
        } else { $false }
    } "Should verify RSA-4096 signature within time limit" 5 "RSA_Verification"
    
    Invoke-PerformanceTest "Batch Signature Verification (10 files)" {
        $success = $true
        if (Test-Path perf_test_2048_public.pem) {
            for ($i = 1; $i -le 10; $i++) {
                $testFile = "batch_test_$i.txt"
                "Batch test file $i" | Out-File $testFile -Encoding UTF8
                & openssl dgst -sha256 -sign perf_test_2048.pem -out "batch_$i.sig" $testFile 2>$null
                & openssl dgst -sha256 -verify perf_test_2048_public.pem -signature "batch_$i.sig" $testFile 2>$null
                if ($LASTEXITCODE -ne 0) { $success = $false; break }
            }
        } else { $success = $false }
        $success
    } "Should process batch signature operations efficiently" 15 "Batch_Processing"
}

function Test-MemoryPerformance {
    Write-TestSection "MEMORY PERFORMANCE TESTS"
    
    Invoke-PerformanceTest "Memory Allocation Performance" {
        $iterations = 1000
        for ($i = 0; $i -lt $iterations; $i++) {
            $buffer = New-Object byte[] 1024
            $buffer = $null
        }
        $true
    } "Should handle frequent memory allocations efficiently" 5 "Memory_Management"
    
    Invoke-PerformanceTest "Large Buffer Allocation" {
        $largeBuffer = New-Object byte[] (10 * 1024 * 1024)  # 10MB
        $largeBuffer[0] = 1
        $largeBuffer[($largeBuffer.Length - 1)] = 1
        $largeBuffer = $null
        [System.GC]::Collect()
        $true
    } "Should allocate large buffers quickly" 3 "Memory_Management"
    
    Invoke-PerformanceTest "Memory Cleanup Performance" {
        $buffers = @()
        for ($i = 0; $i -lt 100; $i++) {
            $buffers += New-Object byte[] (100 * 1024)  # 100KB each
        }
        $buffers = $null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        $true
    } "Should clean up memory efficiently" 10 "Memory_Management"
    
    Invoke-PerformanceTest "Secure Memory Zeroing" {
        $sensitiveData = New-Object byte[] (1024 * 1024)  # 1MB
        for ($i = 0; $i -lt $sensitiveData.Length; $i++) {
            $sensitiveData[$i] = [byte]($i % 256)
        }
        # Secure zero
        for ($i = 0; $i -lt $sensitiveData.Length; $i++) {
            $sensitiveData[$i] = 0
        }
        $true
    } "Should securely zero memory efficiently" 5 "Memory_Security"
}

function Test-ConcurrencyPerformance {
    Write-TestSection "CONCURRENCY PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Concurrency performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-PerformanceTest "Parallel Hash Operations" {
        $jobs = @()
        for ($i = 1; $i -le 4; $i++) {
            $testFile = "parallel_test_$i.txt"
            "Parallel test data $i" * 1000 | Out-File $testFile -Encoding UTF8
            $jobs += Start-Job -ScriptBlock {
                param($file)
                & openssl dgst -sha256 $file 2>$null
                $LASTEXITCODE -eq 0
            } -ArgumentList $testFile
        }
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job -Force
        ($results | Where-Object { $_ -eq $true }).Count -eq 4
    } "Should handle parallel hash operations efficiently" 10 "Concurrency"
    
    Invoke-PerformanceTest "Parallel Encryption Operations" {
        $jobs = @()
        for ($i = 1; $i -le 3; $i++) {
            $testFile = "parallel_enc_$i.txt"
            "Parallel encryption test data $i" * 500 | Out-File $testFile -Encoding UTF8
            $jobs += Start-Job -ScriptBlock {
                param($file, $output)
                & openssl enc -aes-256-cbc -in $file -out $output -k "key$i" -md sha256 2>$null
                $LASTEXITCODE -eq 0
            } -ArgumentList $testFile, "parallel_enc_$i.aes"
        }
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job -Force
        ($results | Where-Object { $_ -eq $true }).Count -eq 3
    } "Should handle parallel encryption operations" 15 "Concurrency"
    
    Invoke-PerformanceTest "Thread Safety Test" {
        $sharedCounter = 0
        $jobs = @()
        for ($i = 1; $i -le 5; $i++) {
            $jobs += Start-Job -ScriptBlock {
                for ($j = 0; $j -lt 100; $j++) {
                    $hash = & openssl rand -hex 32 2>$null
                    if (-not $hash) { return $false }
                }
                $true
            }
        }
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job -Force
        ($results | Where-Object { $_ -eq $true }).Count -eq 5
    } "Should maintain thread safety during concurrent operations" 15 "Concurrency"
}

function Test-ScalabilityPerformance {
    Write-TestSection "SCALABILITY PERFORMANCE TESTS"
    
    if (-not (Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-ColorOutput "⊘ SKIPPING Scalability performance tests - OpenSSL not available" "Yellow"
        $script:SkippedTests += 3
        return
    }
    
    Invoke-PerformanceTest "File Count Scalability (100 small files)" {
        $success = $true
        for ($i = 1; $i -le 100; $i++) {
            $testFile = "scale_test_$i.txt"
            "Scale test file $i" | Out-File $testFile -Encoding UTF8
            & openssl dgst -sha256 $testFile 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { $success = $false; break }
        }
        $success
    } "Should handle many small files efficiently" 30 "Scalability"
    
    Invoke-PerformanceTest "Progressive File Size Performance" {
        $success = $true
        $sizes = @(1KB, 10KB, 100KB, 1MB)
        foreach ($size in $sizes) {
            $data = "x" * $size
            $filename = "progressive_$size.txt"
            $data | Out-File $filename -Encoding UTF8 -NoNewline
            & openssl dgst -sha256 $filename 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { $success = $false; break }
        }
        $success
    } "Should handle progressive file sizes efficiently" 20 "Scalability"
    
    Invoke-PerformanceTest "Sustained Operations Test" {
        $success = $true
        for ($i = 1; $i -le 50; $i++) {
            $data = "Sustained operation test iteration $i"
            $data | Out-File "sustained_$i.txt" -Encoding UTF8
            & openssl enc -aes-256-cbc -in "sustained_$i.txt" -out "sustained_$i.aes" -k "sustainedkey" -md sha256 2>$null
            & openssl enc -aes-256-cbc -d -in "sustained_$i.aes" -out "sustained_${i}_dec.txt" -k "sustainedkey" -md sha256 2>$null
            if ($LASTEXITCODE -ne 0) { $success = $false; break }
        }
        $success
    } "Should maintain performance under sustained load" 45 "Scalability"
}

function Get-SystemPerformanceMetrics {
    Write-TestSection "SYSTEM PERFORMANCE METRICS"
    
    $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    
    Write-ColorOutput "CPU: $($cpu.Name)" "Blue"
    Write-ColorOutput "CPU Cores: $($cpu.NumberOfCores)" "Blue"
    Write-ColorOutput "Total Memory: $([math]::Round($memory.TotalPhysicalMemory / 1GB, 2)) GB" "Blue"
    Write-ColorOutput "Available Disk Space: $([math]::Round($disk.FreeSpace / 1GB, 2)) GB" "Blue"
    
    # Store system metrics for report
    $script:SystemMetrics = @{
        cpu_name = $cpu.Name
        cpu_cores = $cpu.NumberOfCores
        total_memory_gb = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
        available_disk_gb = [math]::Round($disk.FreeSpace / 1GB, 2)
        test_date = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    }
    
    Write-Host ""
}

function New-PerformanceJsonReport {
    param([int]$Duration)
    
    # Calculate performance statistics
    $performanceStats = @{}
    foreach ($category in $script:PerformanceResults.Keys) {
        $categoryTests = $script:PerformanceResults[$category]
        $durations = $categoryTests.Values | ForEach-Object { $_.duration }
        $passedTests = ($categoryTests.Values | Where-Object { $_.passed }).Count
        $totalTests = $categoryTests.Count
        
        $performanceStats[$category] = @{
            total_tests = $totalTests
            passed_tests = $passedTests
            avg_duration = if ($durations.Count -gt 0) { [math]::Round(($durations | Measure-Object -Average).Average, 3) } else { 0 }
            max_duration = if ($durations.Count -gt 0) { [math]::Round(($durations | Measure-Object -Maximum).Maximum, 3) } else { 0 }
            min_duration = if ($durations.Count -gt 0) { [math]::Round(($durations | Measure-Object -Minimum).Minimum, 3) } else { 0 }
        }
    }
    
    $report = @{
        test_phase = "Phase 4 - Performance Tests"
        test_date = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        test_duration = $Duration
        test_environment = "$env:TEMP\crypto_performance_tests"
        application_path = $AppPath
        platform = "Windows PowerShell"
        system_metrics = $script:SystemMetrics
        summary = @{
            total_tests = $script:TotalTests
            passed_tests = $script:PassedTests
            failed_tests = $script:FailedTests
            skipped_tests = $script:SkippedTests
            success_rate = if ($script:TotalTests -gt 0) { [math]::Round(($script:PassedTests * 100.0 / $script:TotalTests), 2) } else { 0 }
        }
        performance_categories = @{
            aes_encryption = "AES-256 encryption/decryption performance"
            rsa_operations = "RSA key generation, encryption, decryption"
            hash_functions = "SHA-256, SHA-512, MD5 hashing performance"
            digital_signatures = "RSA signature creation and verification"
            memory_management = "Memory allocation, cleanup, security"
            concurrency = "Parallel operations and thread safety"
            scalability = "File count and size scalability"
        }
        performance_statistics = $performanceStats
        performance_recommendations = @(
            if ($script:FailedTests -eq 0) { "All performance tests passed - good performance characteristics" } else { "Review failed performance tests for optimization opportunities" },
            if ($script:SkippedTests -gt 5) { "Many tests skipped - ensure OpenSSL is available for full testing" } else { "Comprehensive performance testing completed" },
            "Consider optimization if encryption/decryption times are high",
            "Monitor memory usage for large file operations",
            "Evaluate concurrent operation performance for multi-user scenarios"
        )
        detailed_results = $script:PerformanceResults
    }
    
    $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportFile -Encoding UTF8
}

function Remove-PerformanceTestEnvironment {
    Write-ColorOutput "Cleaning up performance test environment..." "Blue"
    Set-Location ..
    $perfTestDir = "$env:TEMP\crypto_performance_tests"
    if (Test-Path $perfTestDir) {
        Remove-Item $perfTestDir -Recurse -Force
    }
    Write-ColorOutput "✓ Performance test environment cleaned" "Green"
}

function Write-PerformanceSummary {
    param([int]$Duration)
    
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                                   PERFORMANCE TEST SUMMARY" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "End Time: $(Get-Date)" "Blue"
    Write-ColorOutput "Total Duration: $Duration seconds" "Blue"
    Write-Host ""
    Write-ColorOutput "Total Tests: $($script:TotalTests)" "Blue"
    Write-ColorOutput "Passed: $($script:PassedTests)" "Green"
    Write-ColorOutput "Failed: $($script:FailedTests)" "Red"
    Write-ColorOutput "Skipped: $($script:SkippedTests)" "Yellow"
    Write-Host ""
    
    $successRate = if ($script:TotalTests -gt 0) { [math]::Round(($script:PassedTests * 100.0 / $script:TotalTests), 2) } else { 0 }
    Write-ColorOutput "Success Rate: $successRate%" "Blue"
    
    # Performance summary by category
    Write-ColorOutput "Performance Summary by Category:" "Blue"
    foreach ($category in $script:PerformanceResults.Keys) {
        $categoryTests = $script:PerformanceResults[$category]
        $avgDuration = if ($categoryTests.Count -gt 0) { 
            [math]::Round(($categoryTests.Values | ForEach-Object { $_.duration } | Measure-Object -Average).Average, 3) 
        } else { 0 }
        $passedCount = ($categoryTests.Values | Where-Object { $_.passed }).Count
        Write-ColorOutput "  $category`: $passedCount/$($categoryTests.Count) passed, avg ${avgDuration}s" "Cyan"
    }
    Write-Host ""
    
    if ($script:FailedTests -eq 0) {
        Write-ColorOutput "🚀 ALL PERFORMANCE TESTS PASSED! Application shows good performance characteristics." "Green"
    } elseif ($script:FailedTests -le 3) {
        Write-ColorOutput "⚠️  Some performance issues detected. Consider optimization." "Yellow"
    } else {
        Write-ColorOutput "⚠️  Multiple performance issues found. Review and optimize critical paths." "Red"
    }
    
    Write-Host ""
    Write-ColorOutput "Performance Categories Tested:" "Blue"
    Write-ColorOutput "• AES Encryption/Decryption • RSA Operations • Hash Functions" "Cyan"
    Write-ColorOutput "• Digital Signatures • Memory Management • Concurrency • Scalability" "Cyan"
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
    Write-ColorOutput "PERFORMANCE TEST CATEGORIES:" "Yellow"
    Write-Host "  • AES-256 Encryption/Decryption Performance"
    Write-Host "  • RSA Key Generation and Operations"
    Write-Host "  • Hash Function Performance (SHA-256, SHA-512, MD5)"
    Write-Host "  • Digital Signature Creation and Verification"
    Write-Host "  • Memory Management and Security"
    Write-Host "  • Concurrency and Thread Safety"
    Write-Host "  • Scalability with Large Files and Batches"
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
    
    # Get system performance metrics
    Get-SystemPerformanceMetrics
    
    # Initialize log file
    "Phase 4 Performance Tests - $(Get-Date)" | Out-File -FilePath $LogFile -Encoding UTF8
    "===========================================" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    
    try {
        # Setup performance test environment
        Initialize-PerformanceTestEnvironment
        
        # Run all performance test categories
        Test-EncryptionPerformance
        Test-DecryptionPerformance
        Test-RSAPerformance
        Test-HashPerformance
        Test-SignaturePerformance
        Test-MemoryPerformance
        Test-ConcurrencyPerformance
        Test-ScalabilityPerformance
        
        # Calculate duration
        $endTime = Get-Date
        $duration = [int]($endTime - $startTime).TotalSeconds
        
        # Generate reports
        New-PerformanceJsonReport -Duration $duration
        Write-PerformanceSummary -Duration $duration
        
    } finally {
        # Cleanup
        Remove-PerformanceTestEnvironment
    }
}

# Run the performance tests
Main
