#include "utils/key_generator.h"
#include "cryptography/rsa_crypto.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <chrono>
#include <algorithm>
#include <array>
#include <set>
#include <cmath>
#include <sstream>
#include <iomanip>

namespace CryptoApp {

KeyGenerator::KeyGenerator() : gen(rd()) {
    seedGenerator();
}

KeyGenerator::~KeyGenerator() {}

void KeyGenerator::seedGenerator() {
    // Use multiple entropy sources
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = now.time_since_epoch().count();
    
    std::vector<std::uint32_t> seeds;
    seeds.push_back(rd());
    seeds.push_back(static_cast<std::uint32_t>(timestamp));
    seeds.push_back(static_cast<std::uint32_t>(timestamp >> 32));
    
    std::seed_seq seq(seeds.begin(), seeds.end());
    gen.seed(seq);
}

ByteVector KeyGenerator::generateRandomBytes(size_t length) {
    ByteVector bytes(length);
    
    // Use OpenSSL's RAND_bytes for cryptographically secure random generation
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
        // Fallback to C++ random if OpenSSL fails
        std::uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = static_cast<unsigned char>(dis(gen));
        }
    }
    
    return bytes;
}

ByteVector KeyGenerator::generateAESKey(int keySize) {
    size_t keySizeBytes = keySize / 8;  // Convert bits to bytes
    return generateRandomBytes(keySizeBytes);
}

ByteVector KeyGenerator::generateBlowfishKey(int keySize) {
    size_t keySizeBytes = std::min(keySize / 8, 56); // Blowfish max key size is 448 bits (56 bytes)
    return generateRandomBytes(keySizeBytes);
}

KeyPair KeyGenerator::generateRSAKeyPair(int keySize) {
    RSACrypto rsa;
    return rsa.generateKeyPair();
}

std::string KeyGenerator::generateSecurePassword(int length, 
                                                bool includeUppercase,
                                                bool includeLowercase,
                                                bool includeNumbers,
                                                bool includeSymbols) {
    std::string characters = "";
    
    if (includeUppercase) characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeLowercase) characters += "abcdefghijklmnopqrstuvwxyz";
    if (includeNumbers) characters += "0123456789";
    if (includeSymbols) characters += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    if (characters.empty()) {
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    }
    
    std::uniform_int_distribution<> dis(0, characters.length() - 1);
    std::string password;
    password.reserve(length);
    
    for (int i = 0; i < length; ++i) {
        password += characters[dis(gen)];
    }
    
    return password;
}

ByteVector KeyGenerator::generateSalt(size_t length) {
    return generateRandomBytes(length);
}

ByteVector KeyGenerator::generateIV(size_t length) {
    return generateRandomBytes(length);
}

std::string KeyGenerator::generateUUID() {
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    ss << std::hex;
    
    for (int i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    for (int i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4"; // Version 4 UUID
    
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    ss << dis2(gen); // Variant bits
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    for (int i = 0; i < 12; i++) {
        ss << dis(gen);
    }
    
    return ss.str();
}

KeyGenerator::KeyStrength KeyGenerator::evaluatePasswordStrength(const std::string& password) {
    KeyStrength strength;
    strength.score = 0;
    
    // Length scoring
    int lengthScore = std::min(password.length() * 2, 25UL);
    strength.score += lengthScore;
    
    // Character variety scoring
    int varietyScore = 0;
    if (hasUppercase(password)) varietyScore += 10;
    if (hasLowercase(password)) varietyScore += 10;
    if (hasNumbers(password)) varietyScore += 10;
    if (hasSymbols(password)) varietyScore += 15;
    
    strength.score += varietyScore;
    
    // Complexity scoring
    strength.score += calculateComplexityScore(password);
    
    // Determine strength level
    if (strength.score < 30) {
        strength.level = "Weak";
        strength.recommendations.push_back("Use at least 8 characters");
        strength.recommendations.push_back("Include uppercase and lowercase letters");
        strength.recommendations.push_back("Include numbers and symbols");
    } else if (strength.score < 50) {
        strength.level = "Medium";
        strength.recommendations.push_back("Consider adding more characters");
        if (!hasSymbols(password)) {
            strength.recommendations.push_back("Add symbols for better security");
        }
    } else if (strength.score < 75) {
        strength.level = "Strong";
        if (password.length() < 12) {
            strength.recommendations.push_back("Consider using 12+ characters for maximum security");
        }
    } else {
        strength.level = "Very Strong";
    }
    
    // Cap the score at 100
    strength.score = std::min(strength.score, 100);
    
    return strength;
}

int KeyGenerator::generateRandomInt(int min, int max) {
    std::uniform_int_distribution<int> dis(min, max);
    return dis(gen);
}

double KeyGenerator::generateRandomDouble(double min, double max) {
    std::uniform_real_distribution<double> dis(min, max);
    return dis(gen);
}

ByteVector KeyGenerator::deriveKeyPBKDF2(const std::string& password, 
                                        const ByteVector& salt,
                                        int iterations,
                                        size_t keyLength) {
    ByteVector derivedKey(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          iterations,
                          EVP_sha256(),
                          keyLength,
                          derivedKey.data()) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    
    return derivedKey;
}

double KeyGenerator::calculateEntropy(const ByteVector& data) {
    if (data.empty()) return 0.0;
    
    // Count frequency of each byte value
    std::array<int, 256> frequency = {};
    for (unsigned char byte : data) {
        frequency[byte]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    double dataSize = static_cast<double>(data.size());
    
    for (int count : frequency) {
        if (count > 0) {
            double probability = count / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

bool KeyGenerator::isHighEntropyData(const ByteVector& data, double threshold) {
    return calculateEntropy(data) >= threshold;
}

bool KeyGenerator::hasUppercase(const std::string& str) {
    return std::any_of(str.begin(), str.end(), [](char c) { return std::isupper(c); });
}

bool KeyGenerator::hasLowercase(const std::string& str) {
    return std::any_of(str.begin(), str.end(), [](char c) { return std::islower(c); });
}

bool KeyGenerator::hasNumbers(const std::string& str) {
    return std::any_of(str.begin(), str.end(), [](char c) { return std::isdigit(c); });
}

bool KeyGenerator::hasSymbols(const std::string& str) {
    return std::any_of(str.begin(), str.end(), [](char c) { 
        return !std::isalnum(c) && !std::isspace(c); 
    });
}

int KeyGenerator::calculateComplexityScore(const std::string& password) {
    int score = 0;
    
    // Check for patterns and repetition
    std::set<char> uniqueChars(password.begin(), password.end());
    double uniqueRatio = static_cast<double>(uniqueChars.size()) / password.length();
    score += static_cast<int>(uniqueRatio * 20);
    
    // Check for sequential characters
    int sequentialCount = 0;
    for (size_t i = 1; i < password.length(); ++i) {
        if (std::abs(password[i] - password[i-1]) == 1) {
            sequentialCount++;
        }
    }
    
    // Penalize sequential characters
    if (sequentialCount > password.length() / 3) {
        score -= 10;
    }
    
    // Check for common patterns
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    std::vector<std::string> commonPatterns = {
        "password", "123456", "qwerty", "abc", "admin", "user", "login"
    };
    
    for (const auto& pattern : commonPatterns) {
        if (lower.find(pattern) != std::string::npos) {
            score -= 15;
        }
    }
    
    return std::max(score, 0);
}

} // namespace CryptoApp
