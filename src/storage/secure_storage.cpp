#include "storage/secure_storage.h"
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

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
        pt::ptree tree;
        pt::read_json(metadataFile, tree);
        
        metadata.clear();
        
        for (const auto& item : tree.get_child("files")) {
            const auto& fileData = item.second;
            FileMetadata meta;
            
            meta.originalName = fileData.get<std::string>("originalName");
            meta.encryptedName = fileData.get<std::string>("encryptedName");
            meta.hash = fileData.get<std::string>("hash");
            meta.hashAlgorithm = static_cast<HashAlgorithm>(
                fileData.get<int>("hashAlgorithm"));
            meta.timestamp = fileData.get<std::string>("timestamp");
            meta.originalSize = fileData.get<size_t>("originalSize");
            meta.encryptedSize = fileData.get<size_t>("encryptedSize");
            
            metadata[item.first] = meta;
        }
        
    } catch (const pt::ptree_error& e) {
        throw std::runtime_error("Failed to load metadata: " + std::string(e.what()));
    }
}

void SecureStorage::saveMetadata() {
    try {
        pt::ptree tree;
        pt::ptree filesTree;
        
        for (const auto& item : metadata) {
            pt::ptree fileTree;
            const auto& meta = item.second;
            
            fileTree.put("originalName", meta.originalName);
            fileTree.put("encryptedName", meta.encryptedName);
            fileTree.put("hash", meta.hash);
            fileTree.put("hashAlgorithm", static_cast<int>(meta.hashAlgorithm));
            fileTree.put("timestamp", meta.timestamp);
            fileTree.put("originalSize", meta.originalSize);
            fileTree.put("encryptedSize", meta.encryptedSize);
            
            filesTree.put_child(item.first, fileTree);
        }
        
        tree.put_child("files", filesTree);
        tree.put("version", "1.0");
        tree.put("created", getCurrentTimestamp());
        
        pt::write_json(metadataFile, tree);
        
    } catch (const pt::ptree_error& e) {
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
