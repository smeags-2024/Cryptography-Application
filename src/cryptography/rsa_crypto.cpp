#include "cryptography/rsa_crypto.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <memory>

namespace CryptoApp {

RSACrypto::RSACrypto() {
    OpenSSL_add_all_algorithms();
}

RSACrypto::~RSACrypto() {
    EVP_cleanup();
}

KeyPair RSACrypto::generateKeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        throw std::runtime_error("Failed to create key generation context");
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize key generation");
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set key size");
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate key pair");
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Extract public key
    BIO* pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBio, pkey);
    
    char* pubData;
    long pubLen = BIO_get_mem_data(pubBio, &pubData);
    std::string publicKey(pubData, pubLen);
    BIO_free(pubBio);
    
    // Extract private key
    BIO* privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privBio, pkey, NULL, NULL, 0, NULL, NULL);
    
    char* privData;
    long privLen = BIO_get_mem_data(privBio, &privData);
    std::string privateKey(privData, privLen);
    BIO_free(privBio);
    
    EVP_PKEY_free(pkey);
    
    return std::make_pair(publicKey, privateKey);
}

EVP_PKEY* RSACrypto::loadPublicKeyFromString(const std::string& publicKeyStr) {
    BIO* bio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return pkey;
}

EVP_PKEY* RSACrypto::loadPrivateKeyFromString(const std::string& privateKeyStr) {
    BIO* bio = BIO_new_mem_buf(privateKeyStr.c_str(), -1);
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return pkey;
}

OperationResult RSACrypto::encryptWithPublicKey(const ByteVector& plaintext, 
                                              const std::string& publicKey) {
    try {
        EVP_PKEY* pkey = loadPublicKeyFromString(publicKey);
        if (!pkey) {
            return OperationResult(false, "Failed to load public key");
        }
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to create encryption context");
        }
        
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to initialize encryption");
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to set padding");
        }
        
        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to determine ciphertext length");
        }
        
        ByteVector ciphertext(outlen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to encrypt data");
        }
        
        ciphertext.resize(outlen);
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        return OperationResult(true, "Encryption successful", ciphertext);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("RSA encryption error: ") + e.what());
    }
}

OperationResult RSACrypto::encryptWithPublicKey(const std::string& plaintext, 
                                              const std::string& publicKey) {
    ByteVector data(plaintext.begin(), plaintext.end());
    return encryptWithPublicKey(data, publicKey);
}

OperationResult RSACrypto::decryptWithPrivateKey(const ByteVector& ciphertext, 
                                                const std::string& privateKey) {
    try {
        EVP_PKEY* pkey = loadPrivateKeyFromString(privateKey);
        if (!pkey) {
            return OperationResult(false, "Failed to load private key");
        }
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx) {
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to create decryption context");
        }
        
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to initialize decryption");
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to set padding");
        }
        
        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to determine plaintext length");
        }
        
        ByteVector plaintext(outlen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return OperationResult(false, "Failed to decrypt data");
        }
        
        plaintext.resize(outlen);
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        
        return OperationResult(true, "Decryption successful", plaintext);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("RSA decryption error: ") + e.what());
    }
}

OperationResult RSACrypto::decryptWithPrivateKeyToString(const ByteVector& ciphertext, 
                                                       const std::string& privateKey) {
    auto result = decryptWithPrivateKey(ciphertext, privateKey);
    if (result.success) {
        std::string plaintext(result.data.begin(), result.data.end());
        return OperationResult(true, result.message, ByteVector(plaintext.begin(), plaintext.end()));
    }
    return result;
}

OperationResult RSACrypto::saveKeyPairToFiles(const KeyPair& keyPair,
                                            const std::string& publicKeyFile,
                                            const std::string& privateKeyFile) {
    try {
        // Save public key
        std::ofstream pubFile(publicKeyFile);
        if (!pubFile) {
            return OperationResult(false, "Cannot create public key file");
        }
        pubFile << keyPair.first;
        pubFile.close();
        
        // Save private key
        std::ofstream privFile(privateKeyFile);
        if (!privFile) {
            return OperationResult(false, "Cannot create private key file");
        }
        privFile << keyPair.second;
        privFile.close();
        
        return OperationResult(true, "Key pair saved successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Key save error: ") + e.what());
    }
}

KeyPair RSACrypto::loadKeyPairFromFiles(const std::string& publicKeyFile,
                                      const std::string& privateKeyFile) {
    std::ifstream pubFile(publicKeyFile);
    std::ifstream privFile(privateKeyFile);
    
    if (!pubFile || !privFile) {
        throw std::runtime_error("Cannot open key files");
    }
    
    std::stringstream pubBuffer, privBuffer;
    pubBuffer << pubFile.rdbuf();
    privBuffer << privFile.rdbuf();
    
    return std::make_pair(pubBuffer.str(), privBuffer.str());
}

KeyInfo RSACrypto::getKeyInfo(const std::string& key) {
    KeyInfo info;
    info.algorithm = "RSA";
    info.keySize = KEY_SIZE;
    info.format = "PEM";
    
    // Generate a simple fingerprint (hash of the key)
    std::hash<std::string> hasher;
    size_t hashValue = hasher(key);
    
    std::stringstream ss;
    ss << std::hex << hashValue;
    info.fingerprint = ss.str().substr(0, 16); // First 16 characters
    
    return info;
}

} // namespace CryptoApp
