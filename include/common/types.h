#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <vector>
#include <memory>

namespace CryptoApp {

    // Type definitions
    using ByteVector = std::vector<unsigned char>;
    using KeyPair = std::pair<std::string, std::string>; // public, private
    
    // Encryption algorithms enum
    enum class EncryptionAlgorithm {
        AES_256,
        RSA_2048,
        BLOWFISH
    };
    
    // Hash algorithms enum
    enum class HashAlgorithm {
        MD5,
        SHA256
    };
    
    // File types enum
    enum class FileType {
        TEXT,
        BINARY,
        UNKNOWN
    };
    
    // Operation result structure
    struct OperationResult {
        bool success;
        std::string message;
        ByteVector data;
        
        OperationResult(bool s = false, const std::string& msg = "", const ByteVector& d = {})
            : success(s), message(msg), data(d) {}
    };
    
    // Key information structure
    struct KeyInfo {
        std::string algorithm;
        int keySize;
        std::string format;
        std::string fingerprint;
    };
    
    // Signature verification result
    struct SignatureResult {
        bool isValid;
        std::string signerInfo;
        std::string timestamp;
        HashAlgorithm hashAlgorithm;
    };

} // namespace CryptoApp

#endif // TYPES_H
