#ifndef HASH_FUNCTIONS_H
#define HASH_FUNCTIONS_H

#include "common/types.h"
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace CryptoApp {

    class HashFunctions {
    public:
        HashFunctions();
        ~HashFunctions();
        
        // MD5 hash functions
        std::string calculateMD5(const ByteVector& data);
        std::string calculateMD5(const std::string& data);
        std::string calculateMD5File(const std::string& filePath);
        
        // SHA-256 hash functions
        std::string calculateSHA256(const ByteVector& data);
        std::string calculateSHA256(const std::string& data);
        std::string calculateSHA256File(const std::string& filePath);
        
        // Generic hash function
        std::string calculateHash(const ByteVector& data, HashAlgorithm algorithm);
        std::string calculateHash(const std::string& data, HashAlgorithm algorithm);
        std::string calculateHashFile(const std::string& filePath, HashAlgorithm algorithm);
        
        // Verify hash
        bool verifyHash(const ByteVector& data, const std::string& expectedHash, 
                       HashAlgorithm algorithm);
        bool verifyHash(const std::string& data, const std::string& expectedHash, 
                       HashAlgorithm algorithm);
        bool verifyHashFile(const std::string& filePath, const std::string& expectedHash, 
                           HashAlgorithm algorithm);
        
        // HMAC functions
        std::string calculateHMAC_SHA256(const ByteVector& data, const ByteVector& key);
        std::string calculateHMAC_SHA256(const std::string& data, const std::string& key);
        
        // Utility functions
        std::string bytesToHex(const ByteVector& bytes);
        ByteVector hexToBytes(const std::string& hex);
        
    private:
        std::string md5ToHex(const unsigned char* md5);
        std::string sha256ToHex(const unsigned char* sha256);
    };

} // namespace CryptoApp

#endif // HASH_FUNCTIONS_H
