#include "cryptography/digital_signature.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace CryptoApp {

DigitalSignature::DigitalSignature() {
    OpenSSL_add_all_algorithms();
}

DigitalSignature::~DigitalSignature() {
    EVP_cleanup();
}

EVP_PKEY* DigitalSignature::loadPrivateKeyFromString(const std::string& privateKeyStr) {
    BIO* bio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return pkey;
}

EVP_PKEY* DigitalSignature::loadPublicKeyFromString(const std::string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return pkey;
}

const EVP_MD* DigitalSignature::getHashFunction(HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5:
            return EVP_md5();
        case HashAlgorithm::SHA256:
            return EVP_sha256();
        default:
            return EVP_sha256(); // Default to SHA-256
    }
}

std::string DigitalSignature::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

OperationResult DigitalSignature::signData(const ByteVector& data, 
                                         const std::string& privateKey,
                                         HashAlgorithm hashAlgorithm) {
    try {
        EVP_PKEY* pkey = loadPrivateKeyFromString(privateKey);
        if (!pkey) {
            return OperationResult(false, "Failed to load private key");
        }
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to create message digest context");
        }
        
        const EVP_MD* md = getHashFunction(hashAlgorithm);
        
        if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to initialize signing");
        }
        
        if (EVP_DigestSignUpdate(mdctx, data.data(), data.size()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to update signature");
        }
        
        size_t siglen;
        if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to determine signature length");
        }
        
        ByteVector signature(siglen);
        if (EVP_DigestSignFinal(mdctx, signature.data(), &siglen) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to create signature");
        }
        
        signature.resize(siglen);
        
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        
        return OperationResult(true, "Digital signature created successfully", signature);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Signing error: ") + e.what());
    }
}

OperationResult DigitalSignature::signData(const std::string& data, 
                                         const std::string& privateKey,
                                         HashAlgorithm hashAlgorithm) {
    ByteVector dataBytes(data.begin(), data.end());
    return signData(dataBytes, privateKey, hashAlgorithm);
}

OperationResult DigitalSignature::signFile(const std::string& filePath,
                                         const std::string& privateKey,
                                         const std::string& signatureFile,
                                         HashAlgorithm hashAlgorithm) {
    try {
        // Read file content
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            return OperationResult(false, "Cannot open file: " + filePath);
        }
        
        std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
        file.close();
        
        ByteVector fileData(buffer.begin(), buffer.end());
        auto result = signData(fileData, privateKey, hashAlgorithm);
        
        if (result.success) {
            // Save signature to file
            std::ofstream sigFile(signatureFile, std::ios::binary);
            if (!sigFile) {
                return OperationResult(false, "Cannot create signature file");
            }
            
            sigFile.write(reinterpret_cast<const char*>(result.data.data()), result.data.size());
            sigFile.close();
            
            return OperationResult(true, "File signed successfully");
        }
        
        return result;
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File signing error: ") + e.what());
    }
}

SignatureResult DigitalSignature::verifySignature(const ByteVector& data,
                                                const ByteVector& signature,
                                                const std::string& publicKey,
                                                HashAlgorithm hashAlgorithm) {
    SignatureResult result;
    result.isValid = false;
    result.hashAlgorithm = hashAlgorithm;
    result.timestamp = getCurrentTimestamp();
    
    try {
        EVP_PKEY* pkey = loadPublicKeyFromString(publicKey);
        if (!pkey) {
            result.signerInfo = "Failed to load public key";
            return result;
        }
        
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            EVP_PKEY_free(pkey);
            result.signerInfo = "Failed to create message digest context";
            return result;
        }
        
        const EVP_MD* md = getHashFunction(hashAlgorithm);
        
        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            result.signerInfo = "Failed to initialize verification";
            return result;
        }
        
        if (EVP_DigestVerifyUpdate(mdctx, data.data(), data.size()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            result.signerInfo = "Failed to update verification";
            return result;
        }
        
        int verifyResult = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
        
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        
        if (verifyResult == 1) {
            result.isValid = true;
            result.signerInfo = "Signature verification successful";
        } else {
            result.signerInfo = "Signature verification failed";
        }
        
        return result;
        
    } catch (const std::exception& e) {
        result.signerInfo = std::string("Verification error: ") + e.what();
        return result;
    }
}

SignatureResult DigitalSignature::verifySignature(const std::string& data,
                                                const ByteVector& signature,
                                                const std::string& publicKey,
                                                HashAlgorithm hashAlgorithm) {
    ByteVector dataBytes(data.begin(), data.end());
    return verifySignature(dataBytes, signature, publicKey, hashAlgorithm);
}

SignatureResult DigitalSignature::verifyFileSignature(const std::string& filePath,
                                                    const std::string& signatureFile,
                                                    const std::string& publicKey,
                                                    HashAlgorithm hashAlgorithm) {
    SignatureResult result;
    result.isValid = false;
    result.hashAlgorithm = hashAlgorithm;
    result.timestamp = getCurrentTimestamp();
    
    try {
        // Read file content
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            result.signerInfo = "Cannot open file: " + filePath;
            return result;
        }
        
        std::vector<char> buffer((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
        file.close();
        
        // Read signature
        std::ifstream sigFile(signatureFile, std::ios::binary);
        if (!sigFile) {
            result.signerInfo = "Cannot open signature file: " + signatureFile;
            return result;
        }
        
        std::vector<char> sigBuffer((std::istreambuf_iterator<char>(sigFile)),
                                   std::istreambuf_iterator<char>());
        sigFile.close();
        
        ByteVector fileData(buffer.begin(), buffer.end());
        ByteVector signature(sigBuffer.begin(), sigBuffer.end());
        
        return verifySignature(fileData, signature, publicKey, hashAlgorithm);
        
    } catch (const std::exception& e) {
        result.signerInfo = std::string("File verification error: ") + e.what();
        return result;
    }
}

OperationResult DigitalSignature::createDetachedSignature(const std::string& filePath,
                                                         const std::string& privateKey,
                                                         const std::string& signatureFile,
                                                         HashAlgorithm hashAlgorithm) {
    return signFile(filePath, privateKey, signatureFile, hashAlgorithm);
}

SignatureResult DigitalSignature::verifyDetachedSignature(const std::string& filePath,
                                                        const std::string& signatureFile,
                                                        const std::string& publicKey,
                                                        HashAlgorithm hashAlgorithm) {
    return verifyFileSignature(filePath, signatureFile, publicKey, hashAlgorithm);
}

std::string DigitalSignature::getSignatureInfo(const ByteVector& signature) {
    std::stringstream ss;
    ss << "Signature length: " << signature.size() << " bytes\n";
    ss << "Signature (hex): " << hashFunc.bytesToHex(signature).substr(0, 32) << "...\n";
    ss << "Created: " << getCurrentTimestamp();
    return ss.str();
}

} // namespace CryptoApp
