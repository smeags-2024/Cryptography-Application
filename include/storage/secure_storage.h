#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include "common/types.h"
#include "cryptography/aes_crypto.h"
#include "cryptography/hash_functions.h"
#include <boost/filesystem.hpp>
#include <map>

namespace CryptoApp {

    class SecureStorage {
    private:
        AESCrypto aes;
        HashFunctions hashFunc;
        std::string storagePath;
        std::string metadataFile;
        ByteVector masterKey;
        
        struct FileMetadata {
            std::string originalName;
            std::string encryptedName;
            std::string hash;
            HashAlgorithm hashAlgorithm;
            std::string timestamp;
            size_t originalSize;
            size_t encryptedSize;
        };
        
        std::map<std::string, FileMetadata> metadata;
        
        void loadMetadata();
        void saveMetadata();
        std::string generateSecureFileName();
        ByteVector deriveFileKey(const std::string& fileName);
        
    public:
        SecureStorage(const std::string& storagePath);
        ~SecureStorage();
        
        // Initialize secure storage with master password
        OperationResult initialize(const std::string& masterPassword);
        
        // Unlock storage with master password
        OperationResult unlock(const std::string& masterPassword);
        
        // Store file securely
        OperationResult storeFile(const std::string& filePath, 
                                const std::string& alias = "");
        
        // Retrieve file from secure storage
        OperationResult retrieveFile(const std::string& alias, 
                                   const std::string& outputPath);
        
        // List stored files
        std::vector<std::string> listStoredFiles();
        
        // Get file information
        OperationResult getFileInfo(const std::string& alias);
        
        // Delete stored file
        OperationResult deleteFile(const std::string& alias);
        
        // Verify integrity of stored files
        OperationResult verifyIntegrity();
        
        // Change master password
        OperationResult changeMasterPassword(const std::string& oldPassword,
                                           const std::string& newPassword);
        
        // Export storage (for backup)
        OperationResult exportStorage(const std::string& exportPath,
                                    const std::string& password);
        
        // Import storage (from backup)
        OperationResult importStorage(const std::string& importPath,
                                    const std::string& password);
        
        // Storage statistics
        struct StorageStats {
            size_t totalFiles;
            size_t totalSize;
            size_t encryptedSize;
            std::string creationDate;
            std::string lastAccess;
        };
        
        StorageStats getStorageStats();
        
    private:
        std::string getCurrentTimestamp();
        bool isInitialized();
        void createStorageDirectory();
    };

} // namespace CryptoApp

#endif // SECURE_STORAGE_H
