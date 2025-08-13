# Cryptography Application Windows Build Script
# PowerShell script for building the Cryptography Application on Windows
# Requires: PowerShell 5.0+, Visual Studio Build Tools, vcpkg

param(
    [string]$BuildType = "Release",
    [switch]$Install,
    [switch]$Package,
    [switch]$Clean,
    [switch]$Help,
    [switch]$InstallDeps,
    [string]$VcpkgPath = "",
    [string]$QtPath = ""
)

# Script information
$ScriptVersion = "1.0.0"
$ScriptDate = "August 13, 2025"

# Colors for output (if terminal supports ANSI)
$script:UseColors = $true
try {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $script:UseColors = $false
    }
} catch {
    $script:UseColors = $false
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    if ($script:UseColors) {
        switch ($Color) {
            "Red"     { Write-Host $Message -ForegroundColor Red }
            "Green"   { Write-Host $Message -ForegroundColor Green }
            "Yellow"  { Write-Host $Message -ForegroundColor Yellow }
            "Blue"    { Write-Host $Message -ForegroundColor Blue }
            "Cyan"    { Write-Host $Message -ForegroundColor Cyan }
            "Magenta" { Write-Host $Message -ForegroundColor Magenta }
            default   { Write-Host $Message }
        }
    } else {
        Write-Host $Message
    }
}

function Write-Status {
    param([string]$Message)
    Write-ColorOutput "[INFO] $Message" "Blue"
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "[SUCCESS] $Message" "Green"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "[WARNING] $Message" "Yellow"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "[ERROR] $Message" "Red"
}

function Show-Header {
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                    CRYPTOGRAPHY APPLICATION - WINDOWS BUILD SCRIPT" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-Host ""
    Write-Status "Build Script Version: $ScriptVersion"
    Write-Status "Script Date: $ScriptDate"
    Write-Status "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Status "Windows Version: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
    Write-Status "Architecture: $env:PROCESSOR_ARCHITECTURE"
    Write-Host ""
}

function Show-Usage {
    Write-Host ""
    Write-ColorOutput "USAGE:" "Yellow"
    Write-Host "  .\build-windows.ps1 [OPTIONS]"
    Write-Host ""
    Write-ColorOutput "OPTIONS:" "Yellow"
    Write-Host "  -BuildType <type>     Build configuration (Release, Debug, RelWithDebInfo) [Default: Release]"
    Write-Host "  -Install             Install the application after building"
    Write-Host "  -InstallDeps         Automatically install dependencies (requires Administrator)"
    Write-Host "  -Package             Create installation package (.msi)"
    Write-Host "  -Clean               Clean build directory before building"
    Write-Host "  -VcpkgPath <path>    Path to vcpkg installation (auto-detected if not specified)"
    Write-Host "  -QtPath <path>       Path to Qt installation (auto-detected if not specified)"
    Write-Host "  -Help                Show this help message"
    Write-Host ""
    Write-ColorOutput "EXAMPLES:" "Yellow"
    Write-Host "  .\build-windows.ps1                           # Build in Release mode"
    Write-Host "  .\build-windows.ps1 -BuildType Debug          # Build in Debug mode"
    Write-Host "  .\build-windows.ps1 -InstallDeps              # Install dependencies and build"
    Write-Host "  .\build-windows.ps1 -Clean -Install           # Clean build and install"
    Write-Host "  .\build-windows.ps1 -Package                  # Build and create installer"
    Write-Host "  .\build-windows.ps1 -VcpkgPath C:\vcpkg       # Use specific vcpkg path"
    Write-Host ""
    Write-ColorOutput "DEPENDENCIES:" "Yellow"
    Write-Host "  Required: Visual Studio Build Tools, CMake, Git, vcpkg"
    Write-Host "  Optional: Qt5 (for GUI), Chocolatey (for automatic installation)"
    Write-Host ""
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-VcpkgPath {
    $possiblePaths = @(
        "C:\vcpkg",
        "C:\tools\vcpkg",
        "C:\dev\vcpkg",
        "$env:USERPROFILE\vcpkg",
        "$env:VCPKG_ROOT"
    )
    
    foreach ($path in $possiblePaths) {
        if ($path -and (Test-Path "$path\vcpkg.exe")) {
            return $path
        }
    }
    
    # Try to find in PATH
    $vcpkgInPath = Get-Command vcpkg.exe -ErrorAction SilentlyContinue
    if ($vcpkgInPath) {
        return Split-Path $vcpkgInPath.Source -Parent
    }
    
    return $null
}

function Find-QtPath {
    $possiblePaths = @(
        "C:\Qt\5.15.2\msvc2019_64",
        "C:\Qt\5.15.1\msvc2019_64",
        "C:\Qt\5.14.2\msvc2019_64",
        "C:\Qt\5.12.12\msvc2019_64",
        "C:\Tools\Qt\5.15.2\msvc2019_64"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\bin\qmake.exe") {
            return $path
        }
    }
    
    # Check environment variables
    if ($env:QTDIR -and (Test-Path "$env:QTDIR\bin\qmake.exe")) {
        return $env:QTDIR
    }
    
    # Try to find Qt in Program Files
    $qtDirs = Get-ChildItem "C:\Program Files*\Qt*" -Directory -ErrorAction SilentlyContinue
    foreach ($qtDir in $qtDirs) {
        $versions = Get-ChildItem $qtDir.FullName -Directory | Where-Object { $_.Name -match "^5\.\d+\.\d+$" }
        foreach ($version in $versions) {
            $msvcDirs = Get-ChildItem $version.FullName -Directory | Where-Object { $_.Name -match "msvc\d+_64" }
            foreach ($msvcDir in $msvcDirs) {
                if (Test-Path "$($msvcDir.FullName)\bin\qmake.exe") {
                    return $msvcDir.FullName
                }
            }
        }
    }
    
    return $null
}

function Find-VisualStudio {
    # Find Visual Studio installations using vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsInstances = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsInstances) {
            return $vsInstances[0]
        }
    }
    
    # Fallback: check common Visual Studio paths
    $possiblePaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\VC\Auxiliary\Build\vcvars64.bat") {
            return $path
        }
    }
    
    return $null
}

function Install-Chocolatey {
    Write-Status "Installing Chocolatey package manager..."
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh PATH to include Chocolatey
        $env:PATH = "$env:PATH;C:\ProgramData\chocolatey\bin"
        
        # Verify installation
        $chocoInstalled = Get-Command choco.exe -ErrorAction SilentlyContinue
        if ($chocoInstalled) {
            Write-Success "Chocolatey installed successfully"
            return $true
        } else {
            Write-Error "Chocolatey installation verification failed"
            return $false
        }
    } catch {
        Write-Error "Failed to install Chocolatey: $_"
        return $false
    }
}

function Install-VcpkgDependency {
    param([string]$VcpkgRoot)
    
    Write-Status "Installing/updating vcpkg..."
    
    if (-not (Test-Path $VcpkgRoot)) {
        Write-Status "Cloning vcpkg from GitHub..."
        $vcpkgParent = Split-Path $VcpkgRoot -Parent
        if (-not (Test-Path $vcpkgParent)) {
            New-Item -ItemType Directory -Path $vcpkgParent -Force | Out-Null
        }
        
        try {
            & git clone https://github.com/Microsoft/vcpkg.git $VcpkgRoot
        } catch {
            Write-Error "Failed to clone vcpkg: $_"
            return $false
        }
    }
    
    # Bootstrap vcpkg
    $bootstrapScript = "$VcpkgRoot\bootstrap-vcpkg.bat"
    if (Test-Path $bootstrapScript) {
        Write-Status "Bootstrapping vcpkg..."
        try {
            & $bootstrapScript
        } catch {
            Write-Error "Failed to bootstrap vcpkg: $_"
            return $false
        }
    }
    
    return (Test-Path "$VcpkgRoot\vcpkg.exe")
}

function Install-Dependencies {
    param([bool]$AutoInstall = $false)
    
    Write-Status "Checking and installing dependencies..."
    
    # Check if running as administrator
    $isAdmin = Test-Administrator
    if (-not $isAdmin -and $AutoInstall) {
        Write-Error "Administrator privileges required for automatic dependency installation."
        Write-Status "Please run PowerShell as Administrator or install dependencies manually."
        return $false
    }
    
    $allDependenciesOk = $true
    $missingTools = @()
    
    # Check for Chocolatey (install if admin and auto-install)
    $chocoInstalled = Get-Command choco.exe -ErrorAction SilentlyContinue
    if (-not $chocoInstalled -and $AutoInstall -and $isAdmin) {
        if (-not (Install-Chocolatey)) {
            Write-Warning "Failed to install Chocolatey. Manual installation may be required."
        } else {
            $chocoInstalled = Get-Command choco.exe -ErrorAction SilentlyContinue
        }
    }
    
    # Check and install required tools
    $requiredTools = @{
        "cmake.exe" = @{
            Name = "CMake"
            ChocoPackage = "cmake"
            DownloadUrl = "https://cmake.org/download/"
            Description = "CMake build system"
        }
        "git.exe" = @{
            Name = "Git"
            ChocoPackage = "git"
            DownloadUrl = "https://git-scm.com/download/win"
            Description = "Git version control"
        }
    }
    
    foreach ($tool in $requiredTools.Keys) {
        $toolInfo = $requiredTools[$tool]
        $found = Get-Command $tool -ErrorAction SilentlyContinue
        
        if (-not $found) {
            if ($AutoInstall -and $chocoInstalled -and $isAdmin) {
                Write-Status "Installing $($toolInfo.Name) via Chocolatey..."
                try {
                    & choco install $toolInfo.ChocoPackage -y --no-progress
                    $found = Get-Command $tool -ErrorAction SilentlyContinue
                    if ($found) {
                        Write-Success "$($toolInfo.Name) installed successfully"
                    } else {
                        Write-Warning "Failed to install $($toolInfo.Name) via Chocolatey"
                        $missingTools += $toolInfo
                    }
                } catch {
                    Write-Warning "Error installing $($toolInfo.Name): $_"
                    $missingTools += $toolInfo
                }
            } else {
                $missingTools += $toolInfo
            }
        } else {
            Write-Status "$($toolInfo.Name) found: $($found.Source)"
        }
    }
    
    # Check for Visual Studio Build Tools
    $vsPath = Find-VisualStudio
    if (-not $vsPath) {
        if ($AutoInstall -and $chocoInstalled -and $isAdmin) {
            Write-Status "Installing Visual Studio Build Tools via Chocolatey..."
            try {
                & choco install visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools" -y --no-progress
                Start-Sleep 10  # Give time for installation
                $vsPath = Find-VisualStudio
                if ($vsPath) {
                    Write-Success "Visual Studio Build Tools installed successfully"
                } else {
                    Write-Warning "Visual Studio Build Tools installation may need manual verification"
                }
            } catch {
                Write-Warning "Error installing Visual Studio Build Tools: $_"
            }
        }
        
        if (-not $vsPath) {
            $missingTools += @{
                Name = "Visual Studio Build Tools"
                ChocoPackage = "visualstudio2022buildtools"
                DownloadUrl = "https://visualstudio.microsoft.com/downloads/"
                Description = "Visual Studio Build Tools (C++ compiler)"
            }
        }
    } else {
        Write-Status "Visual Studio found: $vsPath"
    }
    
    # Check for vcpkg
    $vcpkgPath = Find-VcpkgPath
    if (-not $vcpkgPath) {
        if ($AutoInstall) {
            $defaultVcpkgPath = "C:\vcpkg"
            Write-Status "Installing vcpkg to $defaultVcpkgPath..."
            if (Install-VcpkgDependency -VcpkgRoot $defaultVcpkgPath) {
                $vcpkgPath = $defaultVcpkgPath
                Write-Success "vcpkg installed successfully"
            } else {
                Write-Warning "Failed to install vcpkg automatically"
                $missingTools += @{
                    Name = "vcpkg"
                    ChocoPackage = "vcpkg"
                    DownloadUrl = "https://github.com/Microsoft/vcpkg"
                    Description = "vcpkg package manager"
                }
            }
        } else {
            $missingTools += @{
                Name = "vcpkg"
                ChocoPackage = "vcpkg"
                DownloadUrl = "https://github.com/Microsoft/vcpkg"
                Description = "vcpkg package manager"
            }
        }
    } else {
        Write-Status "vcpkg found: $vcpkgPath"
    }
    
    # Report missing tools
    if ($missingTools.Count -gt 0) {
        $allDependenciesOk = $false
        Write-Error "Missing required tools:"
        foreach ($tool in $missingTools) {
            Write-Host "  • $($tool.Name): $($tool.Description)"
        }
        Write-Host ""
        Write-Status "Installation options:"
        Write-Host "  1. Run with -InstallDeps as Administrator for automatic installation"
        Write-Host "  2. Install via Chocolatey (as Administrator):"
        foreach ($tool in $missingTools) {
            if ($tool.ChocoPackage) {
                Write-Host "     choco install $($tool.ChocoPackage)"
            }
        }
        Write-Host "  3. Manual installation:"
        foreach ($tool in $missingTools) {
            Write-Host "     $($tool.Name): $($tool.DownloadUrl)"
        }
        Write-Host ""
    } else {
        Write-Success "All required dependencies are available"
    }
    
    return $allDependenciesOk
}

function Setup-VcpkgDependencies {
    param([string]$VcpkgRoot)
    
    Write-Status "Setting up vcpkg dependencies..."
    
    if (-not (Test-Path $VcpkgRoot)) {
        Write-Error "vcpkg path not found: $VcpkgRoot"
        throw "vcpkg not found"
    }
    
    $vcpkgExe = "$VcpkgRoot\vcpkg.exe"
    if (-not (Test-Path $vcpkgExe)) {
        Write-Error "vcpkg.exe not found at: $vcpkgExe"
        throw "vcpkg executable not found"
    }
    
    # Install required packages
    $packages = @(
        "openssl:x64-windows",
        "cryptopp:x64-windows",
        "boost:x64-windows"
    )
    
    foreach ($package in $packages) {
        Write-Status "Installing $package..."
        try {
            & $vcpkgExe install $package
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Failed to install $package"
            }
        } catch {
            Write-Warning "Error installing $package: $_"
        }
    }
    
    # Integrate vcpkg with Visual Studio
    Write-Status "Integrating vcpkg with Visual Studio..."
    & $vcpkgExe integrate install
    
    Write-Success "vcpkg dependencies setup completed"
}

function Setup-BuildEnvironment {
    param(
        [string]$VsPath,
        [string]$QtPath,
        [string]$VcpkgPath
    )
    
    Write-Status "Setting up build environment..."
    
    # Setup Visual Studio environment
    $vcvarsPath = "$VsPath\VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $vcvarsPath) {
        Write-Status "Setting up Visual Studio environment..."
        cmd /c "`"$vcvarsPath`" && set" | ForEach-Object {
            if ($_ -match '^([^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
            }
        }
    }
    
    # Add Qt to PATH
    if ($QtPath) {
        $env:PATH = "$QtPath\bin;$env:PATH"
        $env:Qt5_DIR = "$QtPath\lib\cmake\Qt5"
        Write-Status "Qt5 path set to: $QtPath"
    }
    
    # Add vcpkg to PATH and set toolchain
    if ($VcpkgPath) {
        $env:PATH = "$VcpkgPath;$env:PATH"
        $env:VCPKG_ROOT = $VcpkgPath
        Write-Status "vcpkg path set to: $VcpkgPath"
    }
    
    Write-Success "Build environment configured"
}

function New-BuildDirectory {
    param([bool]$Clean)
    
    Write-Status "Setting up build directory..."
    
    if ($Clean -and (Test-Path "build")) {
        Write-Status "Cleaning existing build directory..."
        Remove-Item "build" -Recurse -Force
    }
    
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" | Out-Null
    }
    
    Set-Location "build"
    Write-Success "Build directory ready"
}

function Invoke-CMakeConfiguration {
    param(
        [string]$BuildType,
        [string]$VcpkgPath,
        [string]$QtPath
    )
    
    Write-Status "Configuring with CMake..."
    
    $cmakeArgs = @(
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DCMAKE_GENERATOR_PLATFORM=x64"
    )
    
    # Add vcpkg toolchain if available
    if ($VcpkgPath) {
        $toolchainFile = "$VcpkgPath\scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $toolchainFile) {
            $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$toolchainFile"
        }
    }
    
    # Add Qt path if specified
    if ($QtPath) {
        $cmakeArgs += "-DCMAKE_PREFIX_PATH=$QtPath"
    }
    
    $cmakeArgs += ".."
    
    Write-Status "CMake command: cmake $($cmakeArgs -join ' ')"
    
    try {
        & cmake @cmakeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed with exit code $LASTEXITCODE"
        }
        Write-Success "CMake configuration completed"
    } catch {
        Write-Error "CMake configuration failed: $_"
        Write-Host ""
        Write-Status "Troubleshooting tips:"
        Write-Host "  1. Ensure all dependencies are installed via vcpkg"
        Write-Host "  2. Check CMake version (requires 3.10+)"
        Write-Host "  3. Verify Qt5 installation path"
        Write-Host "  4. Ensure Visual Studio Build Tools are installed"
        Write-Host "  5. Try running from Visual Studio Developer Command Prompt"
        throw
    }
}

function Invoke-Build {
    param([string]$BuildType)
    
    Write-Status "Building application..."
    
    try {
        & cmake --build . --config $BuildType --parallel
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed with exit code $LASTEXITCODE"
        }
        Write-Success "Build completed successfully"
    } catch {
        Write-Error "Build failed: $_"
        throw
    }
}

function Invoke-Tests {
    Write-Status "Running tests..."
    
    try {
        if (Test-Path "CTest") {
            & ctest --output-on-failure
            if ($LASTEXITCODE -eq 0) {
                Write-Success "All tests passed"
            } else {
                Write-Warning "Some tests failed (exit code: $LASTEXITCODE)"
            }
        } else {
            Write-Warning "No tests found"
        }
    } catch {
        Write-Warning "Test execution failed: $_"
    }
}

function New-Package {
    Write-Status "Creating installation package..."
    
    try {
        if (Get-Command cpack.exe -ErrorAction SilentlyContinue) {
            & cpack -G WIX
            if ($LASTEXITCODE -eq 0) {
                Write-Success "Installation package created"
            } else {
                Write-Warning "Package creation failed"
            }
        } else {
            Write-Warning "CPack not available, skipping package creation"
        }
    } catch {
        Write-Warning "Package creation failed: $_"
    }
}

function Install-Application {
    Write-Status "Installing application..."
    
    if (-not (Test-Administrator)) {
        Write-Error "Administrator privileges required for installation"
        throw "Installation requires administrator privileges"
    }
    
    try {
        & cmake --install . --config $BuildType
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Application installed successfully"
        } else {
            Write-Warning "Installation failed"
        }
    } catch {
        Write-Error "Installation failed: $_"
        throw
    }
}

function Show-Summary {
    param(
        [string]$BuildType,
        [bool]$Install,
        [bool]$Package
    )
    
    Write-Host ""
    Write-ColorOutput "================================================================================================" "Cyan"
    Write-ColorOutput "                                    BUILD SUMMARY" "Cyan"
    Write-ColorOutput "================================================================================================" "Cyan"
    
    Write-Status "Build Type: $BuildType"
    Write-Status "Build completed successfully!"
    
    # Find the executable
    $exePaths = @(
        "src\$BuildType\CryptographyApplication.exe",
        "$BuildType\CryptographyApplication.exe",
        "CryptographyApplication.exe"
    )
    
    $exePath = $null
    foreach ($path in $exePaths) {
        if (Test-Path $path) {
            $exePath = Resolve-Path $path
            break
        }
    }
    
    if ($exePath) {
        Write-Status "Executable location: $exePath"
        Write-Status "To run the application: & '$exePath'"
    } else {
        Write-Warning "Could not locate the built executable"
    }
    
    if ($Package) {
        $msiFiles = Get-ChildItem "*.msi" -ErrorAction SilentlyContinue
        if ($msiFiles) {
            Write-Status "Installation package: $($msiFiles[0].FullName)"
        }
    }
    
    if ($Install) {
        Write-Status "Application has been installed to the system"
    }
    
    Write-Host ""
    Write-Success "Windows build process completed!"
    Write-ColorOutput "================================================================================================" "Cyan"
}

# Main execution
function Main {
    try {
        # Show header
        Show-Header
        
        # Show help if requested
        if ($Help) {
            Show-Usage
            return
        }
        
        # Validate build type
        $validBuildTypes = @("Debug", "Release", "RelWithDebInfo", "MinSizeRel")
        if ($BuildType -notin $validBuildTypes) {
            Write-Error "Invalid build type: $BuildType. Valid options: $($validBuildTypes -join ', ')"
            return
        }
        
        # Install dependencies
        if (-not (Install-Dependencies -AutoInstall $InstallDeps)) {
            if ($InstallDeps) {
                Write-Error "Failed to install required dependencies automatically"
                return
            } else {
                Write-Status "Use -InstallDeps to attempt automatic dependency installation"
                return
            }
        }
        
        # Find vcpkg if not specified
        if (-not $VcpkgPath) {
            $VcpkgPath = Find-VcpkgPath
            if (-not $VcpkgPath) {
                Write-Warning "vcpkg not found. Some dependencies may not be available."
                Write-Status "To install vcpkg:"
                Write-Host "  1. git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg"
                Write-Host "  2. cd C:\vcpkg"
                Write-Host "  3. .\bootstrap-vcpkg.bat"
                Write-Host "  4. .\vcpkg integrate install"
            } else {
                Write-Status "Found vcpkg at: $VcpkgPath"
            }
        }
        
        # Setup vcpkg dependencies
        if ($VcpkgPath -and (Test-Path $VcpkgPath)) {
            Setup-VcpkgDependencies -VcpkgRoot $VcpkgPath
        }
        
        # Find Qt if not specified
        if (-not $QtPath) {
            $QtPath = Find-QtPath
            if (-not $QtPath) {
                Write-Warning "Qt5 not found. Please install Qt5 or specify path with -QtPath"
                Write-Status "Download Qt5 from: https://www.qt.io/download"
            } else {
                Write-Status "Found Qt5 at: $QtPath"
            }
        }
        
        # Find Visual Studio
        $vsPath = Find-VisualStudio
        if (-not $vsPath) {
            Write-Error "Visual Studio or Build Tools not found"
            return
        }
        Write-Status "Found Visual Studio at: $vsPath"
        
        # Setup build environment
        Setup-BuildEnvironment -VsPath $vsPath -QtPath $QtPath -VcpkgPath $VcpkgPath
        
        # Setup build directory
        New-BuildDirectory -Clean $Clean
        
        # Configure with CMake
        Invoke-CMakeConfiguration -BuildType $BuildType -VcpkgPath $VcpkgPath -QtPath $QtPath
        
        # Build the application
        Invoke-Build -BuildType $BuildType
        
        # Run tests
        Invoke-Tests
        
        # Create package if requested
        if ($Package) {
            New-Package
        }
        
        # Install if requested
        if ($Install) {
            Install-Application
        }
        
        # Go back to project root
        Set-Location ..
        
        # Show summary
        Show-Summary -BuildType $BuildType -Install $Install -Package $Package
        
    } catch {
        Write-Error "Build failed: $_"
        if ($_.InnerException) {
            Write-Error "Inner exception: $($_.InnerException.Message)"
        }
        
        # Go back to project root if we're in build directory
        if ((Get-Location).Path.EndsWith("build")) {
            Set-Location ..
        }
        
        exit 1
    }
}

# Run the main function
Main
