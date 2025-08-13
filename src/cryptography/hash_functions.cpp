#include "cryptography/hash_functions.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace CryptoApp {

HashFunctions::HashFunctions() {
    OpenSSL_add_all_algorithms();
}

HashFunctions::~HashFunctions() {
    EVP_cleanup();
}

std::string HashFunctions::calculateMD5(const ByteVector& data) {
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5(data.data(), data.size(), md5);
    return md5ToHex(md5);
}

std::string HashFunctions::calculateMD5(const std::string& data) {
    ByteVector bytes(data.begin(), data.end());
    return calculateMD5(bytes);
}

std::string HashFunctions::calculateMD5File(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filePath);
    }
    
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&md5Context, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        MD5_Update(&md5Context, buffer, file.gcount());
    }
    
    unsigned char md5[MD5_DIGEST_LENGTH];
    MD5_Final(md5, &md5Context);
    
    return md5ToHex(md5);
}

std::string HashFunctions::calculateSHA256(const ByteVector& data) {
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256);
    return sha256ToHex(sha256);
}

std::string HashFunctions::calculateSHA256(const std::string& data) {
    ByteVector bytes(data.begin(), data.end());
    return calculateSHA256(bytes);
}

std::string HashFunctions::calculateSHA256File(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filePath);
    }
    
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256Context, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        SHA256_Update(&sha256Context, buffer, file.gcount());
    }
    
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256_Final(sha256, &sha256Context);
    
    return sha256ToHex(sha256);
}

std::string HashFunctions::calculateHash(const ByteVector& data, HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5:
            return calculateMD5(data);
        case HashAlgorithm::SHA256:
            return calculateSHA256(data);
        default:
            throw std::runtime_error("Unsupported hash algorithm");
    }
}

std::string HashFunctions::calculateHash(const std::string& data, HashAlgorithm algorithm) {
    ByteVector bytes(data.begin(), data.end());
    return calculateHash(bytes, algorithm);
}

std::string HashFunctions::calculateHashFile(const std::string& filePath, HashAlgorithm algorithm) {
    switch (algorithm) {
        case HashAlgorithm::MD5:
            return calculateMD5File(filePath);
        case HashAlgorithm::SHA256:
            return calculateSHA256File(filePath);
        default:
            throw std::runtime_error("Unsupported hash algorithm");
    }
}

bool HashFunctions::verifyHash(const ByteVector& data, const std::string& expectedHash, 
                             HashAlgorithm algorithm) {
    std::string actualHash = calculateHash(data, algorithm);
    return actualHash == expectedHash;
}

bool HashFunctions::verifyHash(const std::string& data, const std::string& expectedHash, 
                             HashAlgorithm algorithm) {
    ByteVector bytes(data.begin(), data.end());
    return verifyHash(bytes, expectedHash, algorithm);
}

bool HashFunctions::verifyHashFile(const std::string& filePath, const std::string& expectedHash, 
                                 HashAlgorithm algorithm) {
    try {
        std::string actualHash = calculateHashFile(filePath, algorithm);
        return actualHash == expectedHash;
    } catch (const std::exception&) {
        return false;
    }
}

std::string HashFunctions::calculateHMAC_SHA256(const ByteVector& data, const ByteVector& key) {
    unsigned char* digest = HMAC(EVP_sha256(), key.data(), key.size(), 
                                data.data(), data.size(), NULL, NULL);
    
    if (!digest) {
        throw std::runtime_error("HMAC calculation failed");
    }
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    
    return ss.str();
}

std::string HashFunctions::calculateHMAC_SHA256(const std::string& data, const std::string& key) {
    ByteVector dataBytes(data.begin(), data.end());
    ByteVector keyBytes(key.begin(), key.end());
    return calculateHMAC_SHA256(dataBytes, keyBytes);
}

std::string HashFunctions::bytesToHex(const ByteVector& bytes) {
    std::stringstream ss;
    for (unsigned char byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

ByteVector HashFunctions::hexToBytes(const std::string& hex) {
    ByteVector bytes;
    
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string length");
    }
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}

std::string HashFunctions::md5ToHex(const unsigned char* md5) {
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md5[i];
    }
    return ss.str();
}

std::string HashFunctions::sha256ToHex(const unsigned char* sha256) {
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)sha256[i];
    }
    return ss.str();
}

} // namespace CryptoApp
