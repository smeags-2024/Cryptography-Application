#ifndef BLOWFISH_CRYPTO_H
#define BLOWFISH_CRYPTO_H

#include "common/types.h"
#include <cryptopp/blowfish.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace CryptoApp {

    class BlowfishCrypto {
    private:
        static const int KEY_SIZE = 32; // 256 bits
        static const int IV_SIZE = 8;   // 64 bits (Blowfish block size)
        
        ByteVector generateKey();
        ByteVector generateIV();
        
    public:
        BlowfishCrypto();
        ~BlowfishCrypto();
        
        // Encrypt data with Blowfish-CBC
        OperationResult encrypt(const ByteVector& plaintext, const ByteVector& key);
        OperationResult encrypt(const std::string& plaintext, const ByteVector& key);
        
        // Decrypt data with Blowfish-CBC
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
        
        // Generate random Blowfish key
        ByteVector generateRandomKey();
        
        // Key derivation from password
        ByteVector deriveKeyFromPassword(const std::string& password, 
                                       const ByteVector& salt);
    };

} // namespace CryptoApp

#endif // BLOWFISH_CRYPTO_H
