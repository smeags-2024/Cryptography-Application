#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "common/types.h"
#include <random>

namespace CryptoApp {

    class KeyGenerator {
    private:
        std::random_device rd;
        std::mt19937 gen;
        
    public:
        KeyGenerator();
        ~KeyGenerator();
        
        // Generate random bytes
        ByteVector generateRandomBytes(size_t length);
        
        // Generate encryption keys
        ByteVector generateAESKey(int keySize = 256); // Key size in bits
        ByteVector generateBlowfishKey(int keySize = 256);
        
        // Generate RSA key pairs
        KeyPair generateRSAKeyPair(int keySize = 2048);
        
        // Generate secure passwords
        std::string generateSecurePassword(int length = 16, 
                                         bool includeUppercase = true,
                                         bool includeLowercase = true,
                                         bool includeNumbers = true,
                                         bool includeSymbols = true);
        
        // Generate salts for key derivation
        ByteVector generateSalt(size_t length = 32);
        
        // Generate initialization vectors
        ByteVector generateIV(size_t length);
        
        // Generate UUIDs/GUIDs
        std::string generateUUID();
        
        // Key strength validation
        struct KeyStrength {
            int score;          // 0-100
            std::string level;  // Weak, Medium, Strong, Very Strong
            std::vector<std::string> recommendations;
        };
        
        KeyStrength evaluatePasswordStrength(const std::string& password);
        
        // Secure random number generation
        int generateRandomInt(int min, int max);
        double generateRandomDouble(double min = 0.0, double max = 1.0);
        
        // Key derivation utilities
        ByteVector deriveKeyPBKDF2(const std::string& password, 
                                  const ByteVector& salt,
                                  int iterations = 10000,
                                  size_t keyLength = 32);
        
        // Entropy testing
        double calculateEntropy(const ByteVector& data);
        bool isHighEntropyData(const ByteVector& data, double threshold = 7.0);
        
    private:
        void seedGenerator();
        bool hasUppercase(const std::string& str);
        bool hasLowercase(const std::string& str);
        bool hasNumbers(const std::string& str);
        bool hasSymbols(const std::string& str);
        int calculateComplexityScore(const std::string& password);
    };

} // namespace CryptoApp

#endif // KEY_GENERATOR_H
