#include "cryptography/aes_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <fstream>
#include <stdexcept>

namespace CryptoApp {

AESCrypto::AESCrypto() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
}

AESCrypto::~AESCrypto() {
    EVP_cleanup();
}

ByteVector AESCrypto::generateKey() {
    ByteVector key(KEY_SIZE);
    if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

ByteVector AESCrypto::generateIV() {
    ByteVector iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random IV");
    }
    return iv;
}

OperationResult AESCrypto::encrypt(const ByteVector& plaintext, const ByteVector& key) {
    if (key.size() != KEY_SIZE) {
        return OperationResult(false, "Invalid key size");
    }
    
    try {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return OperationResult(false, "Failed to create cipher context");
        }
        
        ByteVector iv = generateIV();
        ByteVector ciphertext;
        
        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to initialize encryption");
        }
        
        // Calculate maximum ciphertext length
        int maxCiphertextLen = plaintext.size() + AES_BLOCK_SIZE;
        ciphertext.resize(maxCiphertextLen);
        
        int len;
        int ciphertextLen;
        
        // Encrypt the data
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to encrypt data");
        }
        ciphertextLen = len;
        
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to finalize encryption");
        }
        ciphertextLen += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Prepend IV to ciphertext
        ByteVector result;
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertextLen);
        
        return OperationResult(true, "Encryption successful", result);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Encryption error: ") + e.what());
    }
}

OperationResult AESCrypto::encrypt(const std::string& plaintext, const ByteVector& key) {
    ByteVector data(plaintext.begin(), plaintext.end());
    return encrypt(data, key);
}

OperationResult AESCrypto::decrypt(const ByteVector& ciphertext, const ByteVector& key) {
    if (key.size() != KEY_SIZE) {
        return OperationResult(false, "Invalid key size");
    }
    
    if (ciphertext.size() < IV_SIZE) {
        return OperationResult(false, "Invalid ciphertext size");
    }
    
    try {
        // Extract IV from the beginning of ciphertext
        ByteVector iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
        ByteVector actualCiphertext(ciphertext.begin() + IV_SIZE, ciphertext.end());
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return OperationResult(false, "Failed to create cipher context");
        }
        
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to initialize decryption");
        }
        
        ByteVector plaintext(actualCiphertext.size() + AES_BLOCK_SIZE);
        int len;
        int plaintextLen;
        
        // Decrypt the data
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actualCiphertext.data(), actualCiphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to decrypt data");
        }
        plaintextLen = len;
        
        // Finalize decryption
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return OperationResult(false, "Failed to finalize decryption");
        }
        plaintextLen += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        plaintext.resize(plaintextLen);
        return OperationResult(true, "Decryption successful", plaintext);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Decryption error: ") + e.what());
    }
}

OperationResult AESCrypto::decryptToString(const ByteVector& ciphertext, const ByteVector& key) {
    auto result = decrypt(ciphertext, key);
    if (result.success) {
        std::string plaintext(result.data.begin(), result.data.end());
        return OperationResult(true, result.message, ByteVector(plaintext.begin(), plaintext.end()));
    }
    return result;
}

OperationResult AESCrypto::encryptFile(const std::string& inputFile, 
                                     const std::string& outputFile, 
                                     const ByteVector& key) {
    try {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile) {
            return OperationResult(false, "Cannot open input file");
        }
        
        // Read file content
        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)),
                                std::istreambuf_iterator<char>());
        inFile.close();
        
        ByteVector plaintext(buffer.begin(), buffer.end());
        auto result = encrypt(plaintext, key);
        
        if (result.success) {
            std::ofstream outFile(outputFile, std::ios::binary);
            if (!outFile) {
                return OperationResult(false, "Cannot create output file");
            }
            
            outFile.write(reinterpret_cast<const char*>(result.data.data()), result.data.size());
            outFile.close();
            
            return OperationResult(true, "File encrypted successfully");
        }
        
        return result;
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File encryption error: ") + e.what());
    }
}

OperationResult AESCrypto::decryptFile(const std::string& inputFile, 
                                     const std::string& outputFile, 
                                     const ByteVector& key) {
    try {
        std::ifstream inFile(inputFile, std::ios::binary);
        if (!inFile) {
            return OperationResult(false, "Cannot open input file");
        }
        
        // Read encrypted file content
        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)),
                                std::istreambuf_iterator<char>());
        inFile.close();
        
        ByteVector ciphertext(buffer.begin(), buffer.end());
        auto result = decrypt(ciphertext, key);
        
        if (result.success) {
            std::ofstream outFile(outputFile, std::ios::binary);
            if (!outFile) {
                return OperationResult(false, "Cannot create output file");
            }
            
            outFile.write(reinterpret_cast<const char*>(result.data.data()), result.data.size());
            outFile.close();
            
            return OperationResult(true, "File decrypted successfully");
        }
        
        return result;
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File decryption error: ") + e.what());
    }
}

ByteVector AESCrypto::generateRandomKey() {
    return generateKey();
}

ByteVector AESCrypto::deriveKeyFromPassword(const std::string& password, 
                                          const ByteVector& salt) {
    ByteVector key(KEY_SIZE);
    
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        throw std::runtime_error("Failed to create key derivation context");
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to initialize key derivation");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set hash function");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set salt");
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, 
                                   reinterpret_cast<const unsigned char*>(password.c_str()), 
                                   password.length()) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to set password");
    }
    
    size_t keyLen = KEY_SIZE;
    if (EVP_PKEY_derive(pctx, key.data(), &keyLen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("Failed to derive key");
    }
    
    EVP_PKEY_CTX_free(pctx);
    return key;
}

} // namespace CryptoApp
