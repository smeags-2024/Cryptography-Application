#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include "common/types.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace CryptoApp {

    class AESCrypto {
    private:
        static const int KEY_SIZE = 32; // 256 bits
        static const int IV_SIZE = 16;  // 128 bits
        
        ByteVector generateKey();
        ByteVector generateIV();
        
    public:
        AESCrypto();
        ~AESCrypto();
        
        // Encrypt data with AES-256-CBC
        OperationResult encrypt(const ByteVector& plaintext, const ByteVector& key);
        OperationResult encrypt(const std::string& plaintext, const ByteVector& key);
        
        // Decrypt data with AES-256-CBC
        OperationResult decrypt(const ByteVector& ciphertext, const ByteVector& key);
        OperationResult decryptToString(const ByteVector& ciphertext, const ByteVector& key);
        
        // Encrypt file
        OperationResult encryptFile(const std::string& inputFile, 
                                  const std::string& outputFile, 
                                  const ByteVector& key);
        
        // Decrypt file
        OperationResult decryptFile(const std::string& inputFile, 
                                  const std::string& outputFile, 
                                  const ByteVector& key);
        
        // Generate random AES key
        ByteVector generateRandomKey();
        
        // Key derivation from password
        ByteVector deriveKeyFromPassword(const std::string& password, 
                                       const ByteVector& salt);
    };

} // namespace CryptoApp

#endif // AES_CRYPTO_H
