#include "storage/secure_storage.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>
#include <map>

namespace fs = boost::filesystem;

namespace CryptoApp {

// Simple JSON helper functions
class SimpleJSON {
public:
    static std::string escape(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }
    
    static std::string getValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        
        pos = json.find("\"", pos);
        if (pos == std::string::npos) return "";
        pos++; // Skip opening quote
        
        size_t endPos = json.find("\"", pos);
        if (endPos == std::string::npos) return "";
        
        return json.substr(pos, endPos - pos);
    }
    
    static int getIntValue(const std::string& json, const std::string& key) {
        std::string searchKey = "\"" + key + "\"";
        size_t pos = json.find(searchKey);
        if (pos == std::string::npos) return 0;
        
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        
        // Skip whitespace and find number
        pos++;
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        
        std::string numStr;
        while (pos < json.length() && (std::isdigit(json[pos]) || json[pos] == '-')) {
            numStr += json[pos++];
        }
        
        return numStr.empty() ? 0 : std::stoi(numStr);
    }
    
    static size_t getSizeTValue(const std::string& json, const std::string& key) {
        return static_cast<size_t>(getIntValue(json, key));
    }
};

namespace CryptoApp {

SecureStorage::SecureStorage(const std::string& storagePath) 
    : storagePath(storagePath), metadataFile(storagePath + "/metadata.json") {
    createStorageDirectory();
}

SecureStorage::~SecureStorage() {
    // Clear sensitive data
    std::fill(masterKey.begin(), masterKey.end(), 0);
}

void SecureStorage::createStorageDirectory() {
    try {
        if (!fs::exists(storagePath)) {
            fs::create_directories(storagePath);
        }
    } catch (const fs::filesystem_error& e) {
        throw std::runtime_error("Failed to create storage directory: " + std::string(e.what()));
    }
}

std::string SecureStorage::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool SecureStorage::isInitialized() {
    return fs::exists(metadataFile);
}

std::string SecureStorage::generateSecureFileName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str() + ".enc";
}

ByteVector SecureStorage::deriveFileKey(const std::string& fileName) {
    // Derive a unique key for each file using HKDF
    std::string info = "file_key_" + fileName;
    ByteVector salt(32, 0); // Simple salt for this example
    
    return aes.deriveKeyFromPassword(info, salt);
}

void SecureStorage::loadMetadata() {
    if (!fs::exists(metadataFile)) {
        return; // No metadata file exists yet
    }
    
    try {
        std::ifstream file(metadataFile);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open metadata file");
        }
        
        std::string jsonContent((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
        file.close();
        
        metadata.clear();
        
        // Simple JSON parsing for files section
        size_t filesPos = jsonContent.find("\"files\"");
        if (filesPos == std::string::npos) return;
        
        size_t openBrace = jsonContent.find("{", filesPos);
        if (openBrace == std::string::npos) return;
        
        size_t pos = openBrace + 1;
        while (pos < jsonContent.length()) {
            // Find next file entry key
            size_t keyStart = jsonContent.find("\"", pos);
            if (keyStart == std::string::npos) break;
            keyStart++;
            
            size_t keyEnd = jsonContent.find("\"", keyStart);
            if (keyEnd == std::string::npos) break;
            
            std::string fileId = jsonContent.substr(keyStart, keyEnd - keyStart);
            
            // Find the file data object
            size_t objStart = jsonContent.find("{", keyEnd);
            if (objStart == std::string::npos) break;
            
            size_t objEnd = objStart + 1;
            int braceCount = 1;
            while (objEnd < jsonContent.length() && braceCount > 0) {
                if (jsonContent[objEnd] == '{') braceCount++;
                else if (jsonContent[objEnd] == '}') braceCount--;
                objEnd++;
            }
            
            std::string fileJson = jsonContent.substr(objStart, objEnd - objStart);
            
            FileMetadata meta;
            meta.originalName = SimpleJSON::getValue(fileJson, "originalName");
            meta.encryptedName = SimpleJSON::getValue(fileJson, "encryptedName");
            meta.hash = SimpleJSON::getValue(fileJson, "hash");
            meta.hashAlgorithm = static_cast<HashAlgorithm>(
                SimpleJSON::getIntValue(fileJson, "hashAlgorithm"));
            meta.timestamp = SimpleJSON::getValue(fileJson, "timestamp");
            meta.originalSize = SimpleJSON::getSizeTValue(fileJson, "originalSize");
            meta.encryptedSize = SimpleJSON::getSizeTValue(fileJson, "encryptedSize");
            
            metadata[fileId] = meta;
            
            pos = objEnd;
        }
        
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load metadata: " + std::string(e.what()));
    }
}

void SecureStorage::saveMetadata() {
    try {
        std::stringstream json;
        json << "{\n";
        json << "  \"version\": \"1.0\",\n";
        json << "  \"created\": \"" << SimpleJSON::escape(getCurrentTimestamp()) << "\",\n";
        json << "  \"files\": {\n";
        
        bool first = true;
        for (const auto& item : metadata) {
            if (!first) json << ",\n";
            first = false;
            
            const auto& meta = item.second;
            json << "    \"" << SimpleJSON::escape(item.first) << "\": {\n";
            json << "      \"originalName\": \"" << SimpleJSON::escape(meta.originalName) << "\",\n";
            json << "      \"encryptedName\": \"" << SimpleJSON::escape(meta.encryptedName) << "\",\n";
            json << "      \"hash\": \"" << SimpleJSON::escape(meta.hash) << "\",\n";
            json << "      \"hashAlgorithm\": " << static_cast<int>(meta.hashAlgorithm) << ",\n";
            json << "      \"timestamp\": \"" << SimpleJSON::escape(meta.timestamp) << "\",\n";
            json << "      \"originalSize\": " << meta.originalSize << ",\n";
            json << "      \"encryptedSize\": " << meta.encryptedSize << "\n";
            json << "    }";
        }
        
        json << "\n  }\n";
        json << "}\n";
        
        std::ofstream file(metadataFile);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open metadata file for writing");
        }
        
        file << json.str();
        file.close();
        
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to save metadata: " + std::string(e.what()));
    }
}

OperationResult SecureStorage::initialize(const std::string& masterPassword) {
    if (isInitialized()) {
        return OperationResult(false, "Storage is already initialized");
    }
    
    try {
        // Generate master key from password
        ByteVector salt(32);
        std::random_device rd;
        std::generate(salt.begin(), salt.end(), [&rd] { return rd() % 256; });
        
        masterKey = aes.deriveKeyFromPassword(masterPassword, salt);
        
        // Save salt to a separate file
        std::ofstream saltFile(storagePath + "/salt.bin", std::ios::binary);
        saltFile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        saltFile.close();
        
        // Initialize empty metadata
        metadata.clear();
        saveMetadata();
        
        return OperationResult(true, "Secure storage initialized successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Initialization failed: ") + e.what());
    }
}

OperationResult SecureStorage::unlock(const std::string& masterPassword) {
    if (!isInitialized()) {
        return OperationResult(false, "Storage is not initialized");
    }
    
    try {
        // Load salt
        std::ifstream saltFile(storagePath + "/salt.bin", std::ios::binary);
        if (!saltFile) {
            return OperationResult(false, "Cannot load salt file");
        }
        
        ByteVector salt(32);
        saltFile.read(reinterpret_cast<char*>(salt.data()), salt.size());
        saltFile.close();
        
        // Derive master key
        masterKey = aes.deriveKeyFromPassword(masterPassword, salt);
        
        // Load metadata
        loadMetadata();
        
        return OperationResult(true, "Storage unlocked successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Unlock failed: ") + e.what());
    }
}

OperationResult SecureStorage::storeFile(const std::string& filePath, 
                                       const std::string& alias) {
    if (masterKey.empty()) {
        return OperationResult(false, "Storage is not unlocked");
    }
    
    if (!fs::exists(filePath)) {
        return OperationResult(false, "File does not exist: " + filePath);
    }
    
    try {
        std::string fileAlias = alias.empty() ? fs::path(filePath).filename().string() : alias;
        
        if (metadata.find(fileAlias) != metadata.end()) {
            return OperationResult(false, "File with this alias already exists");
        }
        
        // Generate secure file name
        std::string encryptedFileName = generateSecureFileName();
        std::string encryptedFilePath = storagePath + "/" + encryptedFileName;
        
        // Calculate original file hash
        std::string originalHash = hashFunc.calculateSHA256File(filePath);
        
        // Get file size
        size_t originalSize = fs::file_size(filePath);
        
        // Derive file-specific key
        ByteVector fileKey = deriveFileKey(fileAlias);
        
        // Encrypt file
        auto result = aes.encryptFile(filePath, encryptedFilePath, fileKey);
        if (!result.success) {
            return result;
        }
        
        // Get encrypted file size
        size_t encryptedSize = fs::file_size(encryptedFilePath);
        
        // Create metadata entry
        FileMetadata meta;
        meta.originalName = fs::path(filePath).filename().string();
        meta.encryptedName = encryptedFileName;
        meta.hash = originalHash;
        meta.hashAlgorithm = HashAlgorithm::SHA256;
        meta.timestamp = getCurrentTimestamp();
        meta.originalSize = originalSize;
        meta.encryptedSize = encryptedSize;
        
        metadata[fileAlias] = meta;
        saveMetadata();
        
        return OperationResult(true, "File stored securely with alias: " + fileAlias);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File storage failed: ") + e.what());
    }
}

OperationResult SecureStorage::retrieveFile(const std::string& alias, 
                                          const std::string& outputPath) {
    if (masterKey.empty()) {
        return OperationResult(false, "Storage is not unlocked");
    }
    
    auto it = metadata.find(alias);
    if (it == metadata.end()) {
        return OperationResult(false, "File not found: " + alias);
    }
    
    try {
        const FileMetadata& meta = it->second;
        std::string encryptedFilePath = storagePath + "/" + meta.encryptedName;
        
        if (!fs::exists(encryptedFilePath)) {
            return OperationResult(false, "Encrypted file not found: " + meta.encryptedName);
        }
        
        // Derive file-specific key
        ByteVector fileKey = deriveFileKey(alias);
        
        // Decrypt file
        auto result = aes.decryptFile(encryptedFilePath, outputPath, fileKey);
        if (!result.success) {
            return result;
        }
        
        // Verify file integrity
        std::string retrievedHash = hashFunc.calculateSHA256File(outputPath);
        if (retrievedHash != meta.hash) {
            fs::remove(outputPath); // Remove corrupted file
            return OperationResult(false, "File integrity check failed");
        }
        
        return OperationResult(true, "File retrieved successfully: " + outputPath);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File retrieval failed: ") + e.what());
    }
}

std::vector<std::string> SecureStorage::listStoredFiles() {
    std::vector<std::string> files;
    for (const auto& item : metadata) {
        files.push_back(item.first);
    }
    return files;
}

OperationResult SecureStorage::getFileInfo(const std::string& alias) {
    auto it = metadata.find(alias);
    if (it == metadata.end()) {
        return OperationResult(false, "File not found: " + alias);
    }
    
    const FileMetadata& meta = it->second;
    
    std::stringstream info;
    info << "Alias: " << alias << "\n";
    info << "Original Name: " << meta.originalName << "\n";
    info << "Original Size: " << meta.originalSize << " bytes\n";
    info << "Encrypted Size: " << meta.encryptedSize << " bytes\n";
    info << "Hash (SHA-256): " << meta.hash << "\n";
    info << "Stored: " << meta.timestamp << "\n";
    
    return OperationResult(true, info.str());
}

OperationResult SecureStorage::deleteFile(const std::string& alias) {
    if (masterKey.empty()) {
        return OperationResult(false, "Storage is not unlocked");
    }
    
    auto it = metadata.find(alias);
    if (it == metadata.end()) {
        return OperationResult(false, "File not found: " + alias);
    }
    
    try {
        const FileMetadata& meta = it->second;
        std::string encryptedFilePath = storagePath + "/" + meta.encryptedName;
        
        // Remove encrypted file
        if (fs::exists(encryptedFilePath)) {
            fs::remove(encryptedFilePath);
        }
        
        // Remove from metadata
        metadata.erase(it);
        saveMetadata();
        
        return OperationResult(true, "File deleted successfully: " + alias);
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("File deletion failed: ") + e.what());
    }
}

OperationResult SecureStorage::verifyIntegrity() {
    if (masterKey.empty()) {
        return OperationResult(false, "Storage is not unlocked");
    }
    
    std::stringstream report;
    int totalFiles = 0;
    int corruptedFiles = 0;
    
    for (const auto& item : metadata) {
        totalFiles++;
        const std::string& alias = item.first;
        const FileMetadata& meta = item.second;
        
        std::string encryptedFilePath = storagePath + "/" + meta.encryptedName;
        
        if (!fs::exists(encryptedFilePath)) {
            report << "MISSING: " << alias << " (encrypted file not found)\n";
            corruptedFiles++;
            continue;
        }
        
        // Check encrypted file size
        size_t currentSize = fs::file_size(encryptedFilePath);
        if (currentSize != meta.encryptedSize) {
            report << "CORRUPTED: " << alias << " (size mismatch)\n";
            corruptedFiles++;
            continue;
        }
        
        report << "OK: " << alias << "\n";
    }
    
    report << "\nIntegrity Check Summary:\n";
    report << "Total files: " << totalFiles << "\n";
    report << "Corrupted files: " << corruptedFiles << "\n";
    report << "Healthy files: " << (totalFiles - corruptedFiles) << "\n";
    
    bool success = (corruptedFiles == 0);
    return OperationResult(success, report.str());
}

SecureStorage::StorageStats SecureStorage::getStorageStats() {
    StorageStats stats;
    stats.totalFiles = metadata.size();
    stats.totalSize = 0;
    stats.encryptedSize = 0;
    stats.creationDate = "Unknown";
    stats.lastAccess = getCurrentTimestamp();
    
    for (const auto& item : metadata) {
        const FileMetadata& meta = item.second;
        stats.totalSize += meta.originalSize;
        stats.encryptedSize += meta.encryptedSize;
    }
    
    return stats;
}

} // namespace CryptoApp
