#include "cryptography/blowfish_crypto.h"
#include <cryptopp/blowfish.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <fstream>
#include <stdexcept>

namespace CryptoApp {

BlowfishCrypto::BlowfishCrypto() {
}

BlowfishCrypto::~BlowfishCrypto() {
}

ByteVector BlowfishCrypto::generateKey() {
    CryptoPP::AutoSeededRandomPool rng;
    ByteVector key(KEY_SIZE);
    rng.GenerateBlock(key.data(), KEY_SIZE);
    return key;
}

ByteVector BlowfishCrypto::generateIV() {
    CryptoPP::AutoSeededRandomPool rng;
    ByteVector iv(IV_SIZE);
    rng.GenerateBlock(iv.data(), IV_SIZE);
    return iv;
}

OperationResult BlowfishCrypto::encrypt(const ByteVector& plaintext, const ByteVector& key) {
    if (key.size() > CryptoPP::Blowfish::MAX_KEYLENGTH) {
        return OperationResult(false, "Key size too large for Blowfish");
    }
    
    try {
        ByteVector iv = generateIV();
        ByteVector ciphertext;
        
        CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption encryption;
        encryption.SetKeyWithIV(key.data(), key.size(), iv.data());
        
        CryptoPP::StringSource(
            plaintext.data(), plaintext.size(), true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::VectorSink(ciphertext)
            )
        );
        
        // Prepend IV to ciphertext
        ByteVector result;
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        
        return OperationResult(true, "Blowfish encryption successful", result);
        
    } catch (const CryptoPP::Exception& e) {
        return OperationResult(false, std::string("Blowfish encryption error: ") + e.what());
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Encryption error: ") + e.what());
    }
}

OperationResult BlowfishCrypto::encrypt(const std::string& plaintext, const ByteVector& key) {
    ByteVector data(plaintext.begin(), plaintext.end());
    return encrypt(data, key);
}

OperationResult BlowfishCrypto::decrypt(const ByteVector& ciphertext, const ByteVector& key) {
    if (key.size() > CryptoPP::Blowfish::MAX_KEYLENGTH) {
        return OperationResult(false, "Key size too large for Blowfish");
    }
    
    if (ciphertext.size() < IV_SIZE) {
        return OperationResult(false, "Invalid ciphertext size");
    }
    
    try {
        // Extract IV from the beginning of ciphertext
        ByteVector iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
        ByteVector actualCiphertext(ciphertext.begin() + IV_SIZE, ciphertext.end());
        
        ByteVector plaintext;
        
        CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption decryption;
        decryption.SetKeyWithIV(key.data(), key.size(), iv.data());
        
        CryptoPP::StringSource(
            actualCiphertext.data(), actualCiphertext.size(), true,
            new CryptoPP::StreamTransformationFilter(decryption,
                new CryptoPP::VectorSink(plaintext)
            )
        );
        
        return OperationResult(true, "Blowfish decryption successful", plaintext);
        
    } catch (const CryptoPP::Exception& e) {
        return OperationResult(false, std::string("Blowfish decryption error: ") + e.what());
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Decryption error: ") + e.what());
    }
}

OperationResult BlowfishCrypto::decryptToString(const ByteVector& ciphertext, const ByteVector& key) {
    auto result = decrypt(ciphertext, key);
    if (result.success) {
        std::string plaintext(result.data.begin(), result.data.end());
        return OperationResult(true, result.message, ByteVector(plaintext.begin(), plaintext.end()));
    }
    return result;
}

OperationResult BlowfishCrypto::encryptFile(const std::string& inputFile, 
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
            
            return OperationResult(true, "File encrypted with Blowfish successfully");
        }
        
        return result;
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File encryption error: ") + e.what());
    }
}

OperationResult BlowfishCrypto::decryptFile(const std::string& inputFile, 
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
            
            return OperationResult(true, "File decrypted with Blowfish successfully");
        }
        
        return result;
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File decryption error: ") + e.what());
    }
}

ByteVector BlowfishCrypto::generateRandomKey() {
    return generateKey();
}

ByteVector BlowfishCrypto::deriveKeyFromPassword(const std::string& password, 
                                               const ByteVector& salt) {
    try {
        ByteVector key(KEY_SIZE);
        
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
        pbkdf.DeriveKey(
            key.data(), key.size(),
            0x00, // purpose (not used)
            reinterpret_cast<const unsigned char*>(password.c_str()), password.length(),
            salt.data(), salt.size(),
            10000 // iterations
        );
        
        return key;
        
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error(std::string("Key derivation error: ") + e.what());
    }
}

} // namespace CryptoApp
