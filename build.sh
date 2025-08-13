#!/bin/bash

# Cryptography Application Build Script
# This script automates the build process for the Cryptography Application
# Supports: Linux, macOS, and Unix-like systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# OS Detection
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
        elif [ -f /etc/redhat-release ]; then
            DISTRO="rhel"
        elif [ -f /etc/debian_version ]; then
            DISTRO="debian"
        else
            DISTRO="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    elif [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        DISTRO="cygwin"
    elif [[ "$OSTYPE" == "msys" ]]; then
        OS="windows"
        DISTRO="msys"
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        OS="freebsd"
        DISTRO="freebsd"
    else
        OS="unknown"
        DISTRO="unknown"
    fi
    
    print_status "Detected OS: $OS ($DISTRO)"
}

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Install dependencies automatically
install_dependencies() {
    print_status "Installing dependencies for $DISTRO..."
    
    case "$DISTRO" in
        ubuntu|debian|kali)
            print_status "Updating package database..."
            sudo apt update
            
            print_status "Installing build tools..."
            sudo apt install -y build-essential cmake pkg-config git
            
            print_status "Installing Qt5 development packages..."
            sudo apt install -y qtbase5-dev qttools5-dev qtbase5-dev-tools
            
            print_status "Installing OpenSSL development packages..."
            sudo apt install -y libssl-dev
            
            print_status "Installing Crypto++ development packages..."
            sudo apt install -y libcrypto++-dev
            
            print_status "Installing Boost development packages..."
            sudo apt install -y libboost-all-dev
            ;;
        fedora|rhel|centos)
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            elif command -v yum &> /dev/null; then
                PKG_MANAGER="yum"
            else
                print_error "No package manager found (dnf/yum)"
                return 1
            fi
            
            print_status "Installing build tools..."
            sudo $PKG_MANAGER install -y gcc-c++ cmake pkg-config git make
            
            print_status "Installing Qt5 development packages..."
            sudo $PKG_MANAGER install -y qt5-qtbase-devel qt5-qttools-devel
            
            print_status "Installing OpenSSL development packages..."
            sudo $PKG_MANAGER install -y openssl-devel
            
            print_status "Installing Crypto++ development packages..."
            sudo $PKG_MANAGER install -y cryptopp-devel
            
            print_status "Installing Boost development packages..."
            sudo $PKG_MANAGER install -y boost-devel
            ;;
        arch|manjaro)
            print_status "Installing build tools..."
            sudo pacman -S --needed --noconfirm base-devel cmake pkg-config git
            
            print_status "Installing Qt5 development packages..."
            sudo pacman -S --needed --noconfirm qt5-base qt5-tools
            
            print_status "Installing OpenSSL development packages..."
            sudo pacman -S --needed --noconfirm openssl
            
            print_status "Installing Crypto++ development packages..."
            sudo pacman -S --needed --noconfirm crypto++
            
            print_status "Installing Boost development packages..."
            sudo pacman -S --needed --noconfirm boost
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew is required for macOS. Please install it first:"
                print_status "Visit: https://brew.sh/"
                return 1
            fi
            
            print_status "Installing dependencies via Homebrew..."
            brew install cmake qt5 openssl cryptopp boost pkg-config
            ;;
        opensuse*|suse*)
            print_status "Installing build tools..."
            sudo zypper install -y gcc-c++ cmake pkg-config git make
            
            print_status "Installing Qt5 development packages..."
            sudo zypper install -y libqt5-qtbase-devel libqt5-qttools-devel
            
            print_status "Installing OpenSSL development packages..."
            sudo zypper install -y libopenssl-devel
            
            print_status "Installing Crypto++ development packages..."
            sudo zypper install -y libcryptopp-devel
            
            print_status "Installing Boost development packages..."
            sudo zypper install -y libboost_all-devel
            ;;
        alpine)
            print_status "Installing build tools..."
            sudo apk add --no-cache build-base cmake pkgconfig git
            
            print_status "Installing Qt5 development packages..."
            sudo apk add --no-cache qt5-qtbase-dev qt5-qttools-dev
            
            print_status "Installing OpenSSL development packages..."
            sudo apk add --no-cache openssl-dev
            
            print_status "Installing Crypto++ development packages..."
            sudo apk add --no-cache crypto++-dev
            
            print_status "Installing Boost development packages..."
            sudo apk add --no-cache boost-dev
            ;;
        *)
            print_error "Automatic dependency installation not supported for $DISTRO"
            print_status "Please install dependencies manually:"
            show_install_instructions
            return 1
            ;;
    esac
    
    print_success "Dependencies installed successfully"
}

# Check if dependencies are installed
check_dependencies() {
    local skip_install=${1:-false}
    print_status "Checking dependencies..."
    
    # Check for required tools
    local missing_deps=()
    
    if ! command -v cmake &> /dev/null; then
        missing_deps+=("cmake")
    fi
    
    if ! command -v make &> /dev/null && [ "$OS" != "windows" ]; then
        missing_deps+=("make")
    fi
    
    if ! command -v pkg-config &> /dev/null; then
        missing_deps+=("pkg-config")
    fi
    
    # Check for Qt5
    if ! pkg-config --exists Qt5Core Qt5Widgets 2>/dev/null; then
        missing_deps+=("qt5-devel")
    fi
    
    # Check for OpenSSL
    if ! pkg-config --exists openssl 2>/dev/null; then
        missing_deps+=("openssl-devel")
    fi
    
    # Check for Boost
    if ! find /usr/include -name "boost" -type d 2>/dev/null | head -1 | grep -q boost; then
        if ! find /usr/local/include -name "boost" -type d 2>/dev/null | head -1 | grep -q boost; then
            missing_deps+=("boost-devel")
        fi
    fi
    
    # Check for Crypto++ (try multiple possible locations and names)
    crypto_found=false
    
    # Debug: Print what we're looking for
    if [ "$VERBOSE" = "true" ]; then
        print_status "Checking for Crypto++ libraries..."
    fi
    
    # Check for pkg-config first
    if pkg-config --exists libcrypto++ 2>/dev/null; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ via pkg-config (libcrypto++)"
    elif pkg-config --exists cryptopp 2>/dev/null; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ via pkg-config (cryptopp)"
    # Check for header files in various locations
    elif find /usr/include -name "cryptopp" -type d 2>/dev/null | head -1 | grep -q cryptopp; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ headers in /usr/include/cryptopp"
    elif find /usr/include -name "crypto++" -type d 2>/dev/null | head -1 | grep -q "crypto++"; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ headers in /usr/include/crypto++"
    elif find /usr/local/include -name "cryptopp" -type d 2>/dev/null | head -1 | grep -q cryptopp; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ headers in /usr/local/include/cryptopp"
    elif find /usr/local/include -name "crypto++" -type d 2>/dev/null | head -1 | grep -q "crypto++"; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ headers in /usr/local/include/crypto++"
    # Check for specific header files that are commonly available
    elif [ -f "/usr/include/cryptopp/cryptlib.h" ]; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ header: /usr/include/cryptopp/cryptlib.h"
    elif [ -f "/usr/include/crypto++/cryptlib.h" ]; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ header: /usr/include/crypto++/cryptlib.h"
    elif [ -f "/usr/local/include/cryptopp/cryptlib.h" ]; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ header: /usr/local/include/cryptopp/cryptlib.h"
    elif [ -f "/usr/local/include/crypto++/cryptlib.h" ]; then
        crypto_found=true
        [ "$VERBOSE" = "true" ] && print_status "Found Crypto++ header: /usr/local/include/crypto++/cryptlib.h"
    else
        # Additional debug information
        if [ "$VERBOSE" = "true" ]; then
            print_status "Crypto++ debug info:"
            echo "  pkg-config libcrypto++: $(pkg-config --exists libcrypto++ 2>/dev/null && echo "yes" || echo "no")"
            echo "  pkg-config cryptopp: $(pkg-config --exists cryptopp 2>/dev/null && echo "yes" || echo "no")"
            echo "  /usr/include/cryptopp/ exists: $([ -d "/usr/include/cryptopp" ] && echo "yes" || echo "no")"
            echo "  /usr/include/crypto++/ exists: $([ -d "/usr/include/crypto++" ] && echo "yes" || echo "no")"
            echo "  /usr/include/cryptopp/cryptlib.h exists: $([ -f "/usr/include/cryptopp/cryptlib.h" ] && echo "yes" || echo "no")"
            echo "  /usr/include/crypto++/cryptlib.h exists: $([ -f "/usr/include/crypto++/cryptlib.h" ] && echo "yes" || echo "no")"
            echo "  Listing /usr/include/*crypto*:"
            ls -la /usr/include/*crypto* 2>/dev/null || echo "    No crypto-related directories found"
        fi
    fi
    
    if [ "$crypto_found" = false ]; then
        missing_deps+=("cryptopp-devel")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        
        # Only attempt installation if not already in a re-check
        if [ "$skip_install" = "true" ]; then
            print_error "Dependencies still missing after installation attempt"
            show_install_instructions
            exit 1
        fi
        
        # Ask user if they want to install dependencies automatically
        if [ "$AUTO_INSTALL" = "true" ] || [ "$2" = "--install-deps" ]; then
            print_status "Attempting to install dependencies automatically..."
            if install_dependencies; then
                print_success "Dependencies installed. Re-checking..."
                # Re-check dependencies after installation (with skip_install=true to prevent loops)
                check_dependencies true
                return $?
            else
                print_error "Automatic installation failed. Please install manually:"
                show_install_instructions
                exit 1
            fi
        else
            echo ""
            read -p "Would you like to install dependencies automatically? (y/N): " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                if install_dependencies; then
                    print_success "Dependencies installed. Re-checking..."
                    # Re-check dependencies after installation (with skip_install=true to prevent loops)
                    check_dependencies true
                    return $?
                else
                    print_error "Automatic installation failed. Please install manually:"
                    show_install_instructions
                    exit 1
                fi
            else
                print_status "Please install the missing dependencies manually:"
                show_install_instructions
                exit 1
            fi
        fi
    fi
    
    print_success "All dependencies are available"
}

# Show OS-specific installation instructions
show_install_instructions() {
    echo ""
    case "$DISTRO" in
        ubuntu|debian)
            echo "Ubuntu/Debian:"
            echo "  sudo apt update"
            echo "  sudo apt install build-essential cmake pkg-config"
            echo "  sudo apt install qtbase5-dev qttools5-dev"
            echo "  sudo apt install libssl-dev libcrypto++-dev"
            echo "  sudo apt install libboost-all-dev"
            ;;
        fedora|rhel|centos)
            echo "CentOS/RHEL/Fedora:"
            echo "  sudo dnf install gcc-c++ cmake pkg-config"
            echo "  sudo dnf install qt5-qtbase-devel qt5-qttools-devel"
            echo "  sudo dnf install openssl-devel cryptopp-devel"
            echo "  sudo dnf install boost-devel"
            ;;
        macos)
            echo "macOS (Homebrew):"
            echo "  brew install cmake qt5 openssl cryptopp boost"
            ;;
        arch)
            echo "Arch Linux:"
            echo "  sudo pacman -S base-devel cmake pkg-config"
            echo "  sudo pacman -S qt5-base qt5-tools"
            echo "  sudo pacman -S openssl crypto++ boost"
            ;;
        *)
            echo "Generic Unix/Linux:"
            echo "  Install: cmake, make, pkg-config, Qt5, OpenSSL, Crypto++, Boost"
            echo "  Consult your distribution's package manager documentation"
            ;;
    esac
    
    if [ "$OS" = "windows" ]; then
        echo ""
        echo "Windows:"
        echo "  Use the build-windows.ps1 PowerShell script instead"
        echo "  Or install dependencies via vcpkg/chocolatey"
    fi
}

# Create build directory
setup_build_dir() {
    print_status "Setting up build directory..."
    
    if [ -d "build" ]; then
        print_warning "Build directory exists. Cleaning..."
        rm -rf build
    fi
    
    mkdir -p build
    cd build
    
    print_success "Build directory created"
}

# Configure with CMake
configure_cmake() {
    print_status "Configuring with CMake..."
    
    local cmake_args=""
    local build_type="Release"
    
    # Check for command line arguments
    if [ "$1" = "debug" ]; then
        build_type="Debug"
        print_status "Building in Debug mode"
    else
        print_status "Building in Release mode"
    fi
    
    cmake_args="-DCMAKE_BUILD_TYPE=$build_type"
    
    # OS-specific CMake configuration
    case "$OS" in
        macos)
            # macOS-specific Qt5 paths
            if [ -d "/usr/local/opt/qt5" ]; then
                cmake_args="$cmake_args -DCMAKE_PREFIX_PATH=/usr/local/opt/qt5"
            elif [ -d "/opt/homebrew/opt/qt5" ]; then
                cmake_args="$cmake_args -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt5"
            elif [ -d "/opt/Qt" ]; then
                qt_version=$(find /opt/Qt -maxdepth 1 -name "5.*" | sort -V | tail -1)
                if [ -n "$qt_version" ]; then
                    cmake_args="$cmake_args -DCMAKE_PREFIX_PATH=$qt_version/clang_64"
                fi
            fi
            ;;
        linux)
            # Linux-specific Qt5 paths
            if [ -d "/opt/Qt" ]; then
                qt_version=$(find /opt/Qt -maxdepth 1 -name "5.*" | sort -V | tail -1)
                if [ -n "$qt_version" ]; then
                    cmake_args="$cmake_args -DCMAKE_PREFIX_PATH=$qt_version/gcc_64"
                fi
            fi
            ;;
        windows)
            # Windows-specific paths (if running in WSL/MSYS)
            print_warning "Running on Windows subsystem. Consider using build-windows.ps1 for native Windows build."
            ;;
    esac
    
    if cmake $cmake_args ..; then
        print_success "CMake configuration completed"
    else
        print_error "CMake configuration failed"
        print_status "Troubleshooting tips:"
        echo "  1. Ensure all dependencies are installed"
        echo "  2. Check CMake version (requires 3.10+)"
        echo "  3. Verify Qt5 installation path"
        echo "  4. Try: export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig"
        exit 1
    fi
}

# Build the application
build_application() {
    print_status "Building application..."
    
    local num_cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    print_status "Using $num_cores parallel jobs"
    
    if make -j$num_cores; then
        print_success "Build completed successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Run tests (if available)
run_tests() {
    print_status "Running tests..."
    
    if [ -f "test/run_tests" ]; then
        if ./test/run_tests; then
            print_success "All tests passed"
        else
            print_warning "Some tests failed"
        fi
    else
        print_warning "No tests found"
    fi
}

# Create package (optional)
create_package() {
    print_status "Creating package..."
    
    if command -v cpack &> /dev/null; then
        if cpack; then
            print_success "Package created"
        else
            print_warning "Package creation failed"
        fi
    else
        print_warning "CPack not available, skipping package creation"
    fi
}

# Install application (optional)
install_application() {
    if [ "$1" = "--install" ]; then
        print_status "Installing application..."
        
        if sudo make install; then
            print_success "Application installed successfully"
        else
            print_error "Installation failed"
            exit 1
        fi
    fi
}

# Print usage information
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  debug              Build in debug mode (default: release)"
    echo "  --install          Install the application after building"
    echo "  --install-deps     Automatically install dependencies without prompting"
    echo "  --package          Create installation package"
    echo "  --verbose          Show verbose output during dependency checking"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                        # Build in release mode"
    echo "  $0 debug                  # Build in debug mode"
    echo "  $0 --install-deps         # Install dependencies and build"
    echo "  $0 --verbose              # Build with verbose dependency checking"
    echo "  $0 --install              # Build and install"
    echo "  $0 debug --install        # Build in debug mode and install"
    echo "  $0 --install-deps --install # Install deps, build, and install"
    echo ""
    echo "Supported distributions:"
    echo "  Ubuntu/Debian/Kali, CentOS/RHEL/Fedora, Arch/Manjaro"
    echo "  openSUSE, Alpine Linux, macOS (with Homebrew)"
}

# Main execution
main() {
    print_status "Starting Cryptography Application build process..."
    echo ""
    
    # Detect operating system first
    detect_os
    
    # Check for Windows and suggest PowerShell script
    if [ "$OS" = "windows" ]; then
        print_warning "Windows detected. For native Windows builds, use:"
        echo "  PowerShell: .\\build-windows.ps1"
        echo "  Continuing with Unix-like build process..."
    fi
    
    # Parse command line arguments
    local build_mode="release"
    local install_flag=false
    local package_flag=false
    local auto_install_deps=false
    local verbose_flag=false
    
    for arg in "$@"; do
        case $arg in
            debug)
                build_mode="debug"
                ;;
            --install)
                install_flag=true
                ;;
            --install-deps)
                auto_install_deps=true
                ;;
            --package)
                package_flag=true
                ;;
            --verbose)
                verbose_flag=true
                ;;
            --help)
                print_usage
                exit 0
                ;;
            *)
                print_error "Unknown argument: $arg"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Set environment variables
    if [ "$auto_install_deps" = true ]; then
        export AUTO_INSTALL=true
    fi
    
    if [ "$verbose_flag" = true ]; then
        export VERBOSE=true
    fi
    
    # Execute build steps
    if [ "$auto_install_deps" = true ]; then
        check_dependencies --install-deps
    else
        check_dependencies
    fi
    setup_build_dir
    configure_cmake $build_mode
    build_application
    run_tests
    
    if [ "$package_flag" = true ]; then
        create_package
    fi
    
    if [ "$install_flag" = true ]; then
        install_application --install
    fi
    
    # Go back to project root
    cd ..
    
    echo ""
    print_success "Build process completed!"
    print_status "Executable location: build/CryptographyApplication"
    
    if [ "$install_flag" = false ]; then
        print_status "To install the application, run: sudo make install -C build"
    fi
    
    print_status "To run the application: ./build/CryptographyApplication"
}

# Run main function with all arguments
main "$@"
