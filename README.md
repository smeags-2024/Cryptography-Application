# Cryptography Application

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/Cryptography-Application)
[![Tests](https://img.shields.io/badge/tests-23%2F23%20passing-brightgreen)](https://github.com/yourusername/Cryptography-Application)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/yourusername/Cryptography-Application)

A comprehensive cryptographic tool built in C++ that provides file encryption, digital signatures, hash functions, and secure storage capabilities with a modern GUI interface.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/Cryptography-Application.git
cd Cryptography-Application

# Build with automatic dependency installation
./build.sh

# Run the application
./build/CryptographyApplication
```

## 🧪 Testing

The application includes a comprehensive 5-phase testing framework with **100% success rate** in Phase 1 unit tests:

### Phase 1: Unit Tests ✅ (23/23 passed)
```bash
cd vm-testing/phase1-unit-tests
./run_tests.sh
```

**Test Coverage:**
- ✅ **Dependencies** (5/5): OpenSSL, Qt5, Boost, Crypto++, CMake
- ✅ **Build System** (3/3): Configuration, structure, executable generation  
- ✅ **AES Encryption** (3/3): Key generation, encrypt/decrypt, large data
- ✅ **RSA Encryption** (2/2): Key pair generation, encrypt/decrypt
- ✅ **Hash Functions** (3/3): SHA-256, MD5, deterministic behavior
- ✅ **Digital Signatures** (2/2): File signing and verification
- ✅ **File Operations** (3/3): Read/write, binary handling, large files
- ✅ **Memory Safety** (2/2): Allocation and stack protection

### Phase 2-5: Integration, Security, Performance & Platform Tests
```bash
# Phase 2: Integration Testing
cd vm-testing/phase2-integration-tests && ./run_tests.sh

# Phase 3: Security Testing  
cd vm-testing/phase3-security-tests && ./run_tests.sh

# Phase 4: Performance Testing
cd vm-testing/phase4-performance-tests && ./run_tests.sh

# Phase 5: Platform Testing
cd vm-testing/phase5-platform-tests && ./run_tests.sh
```

## ✨ Features

### 🔐 Encryption Algorithms
- **AES-256**: Advanced Encryption Standard with 256-bit keys
- **RSA-2048**: RSA encryption with 2048-bit keys
- **Blowfish**: Fast block cipher with variable-length keys

### 🔍 Hash Functions
- **SHA-256**: Secure Hash Algorithm 256-bit
- **MD5**: Message Digest Algorithm 5
- **HMAC**: Hash-based Message Authentication Code

### ✍️ Digital Signatures
- RSA digital signatures with SHA-256 and MD5 hashing
- File signing and signature verification
- Detached signature support
- Key pair generation and management

### 🗄️ Secure Storage
- Encrypted file storage with master password protection
- File integrity verification
- Metadata management
- Secure deletion capabilities

### 🖥️ Graphical User Interface
- Modern Qt5-based interface
- Dark theme support
- Tabbed interface for different operations
- Progress tracking and status updates
- Comprehensive logging

## Technologies Used

- **Programming Language**: C++17
- **GUI Framework**: Qt5
- **Cryptographic Libraries**: 
  - OpenSSL (AES, RSA, hash functions, digital signatures)
  - Crypto++ (Blowfish, additional crypto functions)
- **Utilities**: Boost (filesystem, JSON parsing, data structures)
- **Build System**: CMake

## Dependencies

### Required Libraries
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake
sudo apt install qtbase5-dev qttools5-dev
sudo apt install libssl-dev libcrypto++-dev
sudo apt install libboost-all-dev

# CentOS/RHEL/Fedora
sudo dnf install gcc-c++ cmake
sudo dnf install qt5-qtbase-devel qt5-qttools-devel
sudo dnf install openssl-devel cryptopp-devel
sudo dnf install boost-devel

# macOS (using Homebrew)
brew install cmake qt5 openssl cryptopp boost
```

## Building the Application

### Option 1: Automated Build Scripts (Recommended)

#### Linux/macOS/Unix
```bash
# Make the build script executable
chmod +x build.sh

# Build in release mode (default)
./build.sh

# Build in debug mode
./build.sh debug

# Build and install
./build.sh --install

# Build with packaging
./build.sh --package

# Show help
./build.sh --help
```

**Features of the Linux/macOS build script:**
- **OS Detection**: Automatically detects your operating system and distribution
- **Dependency Checking**: Verifies all required dependencies are installed
- **Smart Instructions**: Provides specific installation commands for your platform
- **Qt5 Detection**: Automatically finds Qt5 installations in common locations
- **Error Handling**: Clear error messages and troubleshooting tips

#### Windows
```powershell
# Run PowerShell as Administrator (recommended for dependency installation)

# Build in release mode (default)
.\build-windows.ps1

# Build in debug mode
.\build-windows.ps1 -BuildType Debug

# Build and install (requires admin)
.\build-windows.ps1 -Install

# Build with MSI installer package
.\build-windows.ps1 -Package

# Clean build directory first
.\build-windows.ps1 -Clean

# Specify custom paths
.\build-windows.ps1 -VcpkgPath C:\vcpkg -QtPath C:\Qt\5.15.2\msvc2019_64

# Show help
.\build-windows.ps1 -Help
```

**Features of the Windows PowerShell script:**
- **Automatic Dependency Installation**: Installs tools via Chocolatey if running as admin
- **Smart Path Detection**: Finds Visual Studio, Qt5, and vcpkg automatically
- **vcpkg Integration**: Automatically installs and configures required packages
- **Environment Setup**: Configures Visual Studio build environment
- **MSI Package Creation**: Can create Windows installer packages

### Option 2: Manual Build Process

If you prefer manual control or the automated scripts don't work for your setup:

#### Manual Dependency Installation

##### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential cmake pkg-config
sudo apt install qtbase5-dev qttools5-dev
sudo apt install libssl-dev libcrypto++-dev
sudo apt install libboost-all-dev
```

##### CentOS/RHEL/Fedora
```bash
sudo dnf install gcc-c++ cmake pkg-config
sudo dnf install qt5-qtbase-devel qt5-qttools-devel
sudo dnf install openssl-devel cryptopp-devel
sudo dnf install boost-devel
```

##### macOS (Homebrew)
```bash
brew install cmake qt5 openssl cryptopp boost
```

##### Windows Manual Setup
1. **Visual Studio**: Install Visual Studio 2019/2022 with C++ build tools
2. **CMake**: Download and install from https://cmake.org/download/
3. **Qt5**: Download and install from https://www.qt.io/download
4. **vcpkg**: Install and configure dependencies:
```cmd
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install
.\vcpkg install openssl:x64-windows cryptopp:x64-windows boost:x64-windows
```

#### Manual Build Steps

### 1. Clone the Repository
```bash
git clone <repository-url>
cd Cryptography-Application
```

### 2. Create Build Directory
```bash
mkdir build
cd build
```

### 3. Configure with CMake
```bash
# Basic configuration
cmake ..

# Or with specific Qt5 path (if needed)
cmake -DCMAKE_PREFIX_PATH=/usr/local/opt/qt5 ..

# For Release build
cmake -DCMAKE_BUILD_TYPE=Release ..
```

### 4. Build the Application
```bash
make -j$(nproc)

# Or on Windows
cmake --build . --config Release
```

### 5. Install (Optional)
```bash
sudo make install
```

## Usage

### Running the Application
```bash
# From build directory
./CryptographyApplication

# If installed system-wide
CryptographyApplication
```

### Command Line Interface (Future Enhancement)
```bash
# Example usage (to be implemented)
./CryptographyApplication --encrypt --algorithm AES256 --input file.txt --output file.enc
./CryptographyApplication --hash --algorithm SHA256 --file document.pdf
./CryptographyApplication --sign --file contract.pdf --private-key key.pem
```

## Application Workflow

### 1. File Encryption
1. Select encryption algorithm (AES-256, RSA-2048, or Blowfish)
2. Choose input file to encrypt
3. Specify output location for encrypted file
4. Generate or provide encryption key
5. Execute encryption process

### 2. File Decryption
1. Select matching decryption algorithm
2. Choose encrypted file
3. Specify output location for decrypted file
4. Provide decryption key
5. Execute decryption process

### 3. Hash Calculation
1. Select hash algorithm (SHA-256 or MD5)
2. Choose file to hash
3. View calculated hash value
4. Optionally verify against expected hash

### 4. Digital Signatures
1. Generate RSA key pair or load existing keys
2. **Signing**: Select file, provide private key, generate signature
3. **Verification**: Select file and signature, provide public key, verify authenticity

### 5. Secure Storage
1. Initialize secure storage with master password
2. Store files with automatic encryption
3. Retrieve files with automatic decryption
4. Manage stored files and view metadata

## Security Features

### Key Management
- Cryptographically secure random key generation
- PBKDF2 key derivation from passwords
- Secure key storage and handling
- Key strength evaluation

### File Security
- Multiple encryption algorithms support
- Secure file deletion with overwriting
- File integrity verification
- Metadata protection

### Storage Security
- Master password protection
- Individual file encryption with unique keys
- Salt-based key derivation
- Integrity checking for stored files

## Project Structure

```
Cryptography-Application/
├── CMakeLists.txt              # Build configuration
├── README.md                   # This file
├── include/                    # Header files
│   ├── common/
│   │   └── types.h            # Common type definitions
│   ├── cryptography/
│   │   ├── aes_crypto.h       # AES encryption
│   │   ├── rsa_crypto.h       # RSA encryption
│   │   ├── blowfish_crypto.h  # Blowfish encryption
│   │   ├── hash_functions.h   # Hash algorithms
│   │   └── digital_signature.h # Digital signatures
│   ├── storage/
│   │   └── secure_storage.h   # Secure file storage
│   ├── gui/
│   │   ├── main_window.h      # Main application window
│   │   ├── encryption_dialog.h # Encryption dialog
│   │   ├── decryption_dialog.h # Decryption dialog
│   │   └── signature_dialog.h  # Signature dialog
│   └── utils/
│       ├── file_manager.h     # File operations
│       └── key_generator.h    # Key generation utilities
├── src/                       # Source files
│   ├── main.cpp              # Application entry point
│   ├── cryptography/         # Crypto implementations
│   ├── storage/              # Storage implementations
│   ├── gui/                  # GUI implementations
│   └── utils/                # Utility implementations
└── build/                    # Build directory (generated)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development Guidelines

### Code Style
- Follow C++17 standards
- Use meaningful variable and function names
- Add comprehensive comments for complex algorithms
- Follow RAII principles for resource management

### Security Considerations
- Always validate input parameters
- Use secure random number generation
- Clear sensitive data from memory when possible
- Implement proper error handling
- Follow cryptographic best practices

### Testing
- Unit tests for all cryptographic functions
- Integration tests for GUI components
- Performance benchmarks for encryption algorithms
- Security audits for cryptographic implementations

## Known Issues

- RSA file encryption is limited by key size (use hybrid encryption for large files)
- Some features in dialogs need full implementation
- Command-line interface not yet implemented
- Cross-platform testing needed

## Future Enhancements

- [ ] Command-line interface
- [ ] Additional encryption algorithms (ChaCha20, etc.)
- [ ] Hardware security module (HSM) support
- [ ] Network-based key exchange
- [ ] Plugin architecture for custom algorithms
- [ ] Batch file processing
- [ ] Key escrow and recovery features
- [ ] Audit logging and compliance features

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Disclaimer

This software is provided for educational and research purposes. While it implements standard cryptographic algorithms, it has not undergone formal security auditing. For production use, please conduct thorough security reviews and testing.

## Support

For questions, issues, or contributions, please:
1. Check the existing issues on GitHub
2. Create a new issue with detailed information
3. Contact the development team

## Acknowledgments

- OpenSSL Project for cryptographic functions
- Crypto++ Library for additional algorithms
- Qt Project for the GUI framework
- Boost Libraries for utilities
- The cryptographic community for algorithms and best practices
