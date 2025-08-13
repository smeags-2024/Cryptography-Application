#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

#include "common/types.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace CryptoApp {

    class RSACrypto {
    private:
        static const int KEY_SIZE = 2048;
        static const int PADDING = RSA_PKCS1_OAEP_PADDING;
        
        EVP_PKEY* loadPublicKeyFromString(const std::string& publicKeyStr);
        EVP_PKEY* loadPrivateKeyFromString(const std::string& privateKeyStr);
        
    public:
        RSACrypto();
        ~RSACrypto();
        
        // Generate RSA key pair
        KeyPair generateKeyPair();
        
        // Encrypt with public key
        OperationResult encryptWithPublicKey(const ByteVector& plaintext, 
                                           const std::string& publicKey);
        OperationResult encryptWithPublicKey(const std::string& plaintext, 
                                           const std::string& publicKey);
        
        // Decrypt with private key
        OperationResult decryptWithPrivateKey(const ByteVector& ciphertext, 
                                            const std::string& privateKey);
        OperationResult decryptWithPrivateKeyToString(const ByteVector& ciphertext, 
                                                    const std::string& privateKey);
        
        // Encrypt file with public key
        OperationResult encryptFileWithPublicKey(const std::string& inputFile,
                                                const std::string& outputFile,
                                                const std::string& publicKey);
        
        // Decrypt file with private key
        OperationResult decryptFileWithPrivateKey(const std::string& inputFile,
                                                 const std::string& outputFile,
                                                 const std::string& privateKey);
        
        // Save keys to files
        OperationResult saveKeyPairToFiles(const KeyPair& keyPair,
                                         const std::string& publicKeyFile,
                                         const std::string& privateKeyFile);
        
        // Load keys from files
        KeyPair loadKeyPairFromFiles(const std::string& publicKeyFile,
                                   const std::string& privateKeyFile);
        
        // Get key information
        KeyInfo getKeyInfo(const std::string& key);
    };

} // namespace CryptoApp

#endif // RSA_CRYPTO_H
