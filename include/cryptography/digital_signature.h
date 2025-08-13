#ifndef DIGITAL_SIGNATURE_H
#define DIGITAL_SIGNATURE_H

#include "common/types.h"
#include "cryptography/hash_functions.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace CryptoApp {

    class DigitalSignature {
    private:
        HashFunctions hashFunc;
        
        EVP_PKEY* loadPrivateKeyFromString(const std::string& privateKeyStr);
        EVP_PKEY* loadPublicKeyFromString(const std::string& publicKeyStr);
        
    public:
        DigitalSignature();
        ~DigitalSignature();
        
        // Sign data with private key
        OperationResult signData(const ByteVector& data, 
                               const std::string& privateKey,
                               HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        OperationResult signData(const std::string& data, 
                               const std::string& privateKey,
                               HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Sign file with private key
        OperationResult signFile(const std::string& filePath,
                               const std::string& privateKey,
                               const std::string& signatureFile,
                               HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Verify signature with public key
        SignatureResult verifySignature(const ByteVector& data,
                                      const ByteVector& signature,
                                      const std::string& publicKey,
                                      HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        SignatureResult verifySignature(const std::string& data,
                                      const ByteVector& signature,
                                      const std::string& publicKey,
                                      HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Verify file signature
        SignatureResult verifyFileSignature(const std::string& filePath,
                                          const std::string& signatureFile,
                                          const std::string& publicKey,
                                          HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Create detached signature (signature in separate file)
        OperationResult createDetachedSignature(const std::string& filePath,
                                               const std::string& privateKey,
                                               const std::string& signatureFile,
                                               HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Verify detached signature
        SignatureResult verifyDetachedSignature(const std::string& filePath,
                                              const std::string& signatureFile,
                                              const std::string& publicKey,
                                              HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
        
        // Get signature info
        std::string getSignatureInfo(const ByteVector& signature);
        
    private:
        const EVP_MD* getHashFunction(HashAlgorithm algorithm);
        std::string getCurrentTimestamp();
    };

} // namespace CryptoApp

#endif // DIGITAL_SIGNATURE_H
