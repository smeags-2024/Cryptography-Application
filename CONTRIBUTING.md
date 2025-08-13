# Contributing to Cryptography Application

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/Cryptography-Application.git
   cd Cryptography-Application
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠️ Development Setup

### Prerequisites
- C++17 compatible compiler (GCC 7+, Clang 6+, MSVC 2019+)
- CMake 3.16+
- Qt5 development libraries
- OpenSSL development libraries
- Crypto++ development libraries
- Boost libraries

### Build and Test
```bash
# Build the project
./build.sh

# Run all tests
cd vm-testing/phase1-unit-tests && ./run_tests.sh
```

## 📝 Code Style

### C++ Guidelines
- Follow **C++17** standards
- Use **RAII** principles for resource management
- Prefer **smart pointers** over raw pointers
- Use **const correctness** throughout
- Follow **camelCase** for variables and functions
- Use **PascalCase** for classes and structs

### Example:
```cpp
class CryptoEngine {
private:
    std::unique_ptr<AESCrypto> aesEngine;
    const std::string algorithmName;

public:
    explicit CryptoEngine(const std::string& name) 
        : algorithmName(name) {}
    
    OperationResult encryptFile(const std::string& inputPath, 
                               const std::string& outputPath) const;
};
```

### Documentation
- Use **Doxygen** style comments for public APIs
- Include parameter and return value descriptions
- Add usage examples for complex functions

## 🧪 Testing Requirements

All contributions must include appropriate tests:

### Unit Tests
- Add tests to `vm-testing/phase1-unit-tests/`
- Test new cryptographic functions thoroughly
- Verify error handling and edge cases

### Integration Tests
- Add end-to-end workflow tests to `vm-testing/phase2-integration-tests/`
- Test GUI interactions if applicable

### Security Tests
- Security-related changes require additional validation
- Consider cryptographic best practices

## 🔒 Security Considerations

### Cryptographic Code
- **Never implement custom cryptographic algorithms**
- Use established libraries (OpenSSL, Crypto++)
- Follow cryptographic best practices
- Clear sensitive data from memory when possible

### Input Validation
- Validate all user inputs
- Sanitize file paths and names
- Check buffer boundaries
- Handle errors gracefully

### Code Review
Security-sensitive changes require:
- Detailed code review
- Security testing
- Documentation of security implications

## 📋 Pull Request Process

### Before Submitting
1. **Ensure all tests pass**:
   ```bash
   cd vm-testing/phase1-unit-tests && ./run_tests.sh
   ```
2. **Update documentation** if needed
3. **Add appropriate tests** for new features
4. **Follow code style guidelines**

### Pull Request Guidelines
- **Clear title** describing the change
- **Detailed description** explaining:
  - What changes were made
  - Why the changes were necessary
  - How to test the changes
- **Reference related issues** if applicable
- **Include screenshots** for GUI changes

### Review Process
1. Automated tests must pass
2. Code review by maintainers
3. Security review for cryptographic changes
4. Documentation review
5. Final approval and merge

## 🐛 Bug Reports

### Before Reporting
- Check existing issues for duplicates
- Test with the latest version
- Gather system information

### Bug Report Template
```markdown
**Bug Description**
Clear description of the bug

**Steps to Reproduce**
1. Step one
2. Step two
3. Step three

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Compiler: [e.g., GCC 9.3]
- Qt Version: [e.g., 5.15.2]
- Build Mode: [Debug/Release]

**Additional Context**
Any other relevant information
```

## 💡 Feature Requests

### Feature Request Template
```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why this feature would be useful

**Proposed Implementation**
Ideas for how it could be implemented

**Alternatives Considered**
Other approaches you've considered
```

## 📖 Areas for Contribution

### High Priority
- [ ] Command-line interface implementation
- [ ] Additional encryption algorithms (ChaCha20, AES-GCM)
- [ ] Performance optimizations
- [ ] Cross-platform testing
- [ ] Documentation improvements

### Medium Priority
- [ ] Plugin architecture
- [ ] Batch file processing
- [ ] Key management enhancements
- [ ] GUI improvements
- [ ] Accessibility features

### Low Priority
- [ ] Network features
- [ ] Hardware security module support
- [ ] Audit logging
- [ ] Advanced key recovery

## 📞 Getting Help

- **Documentation**: Check README.md and BUILD_PLAN.md
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Contact maintainers for sensitive issues

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes for significant contributions
- Special recognition for security improvements

Thank you for contributing to making cryptography more accessible and secure!
