#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "common/types.h"
#include <string>
#include <vector>

namespace CryptoApp {

    class FileManager {
    public:
        FileManager();
        ~FileManager();
        
        // File operations
        static bool fileExists(const std::string& filePath);
        static size_t getFileSize(const std::string& filePath);
        static FileType detectFileType(const std::string& filePath);
        static std::string getFileExtension(const std::string& filePath);
        static std::string getFileName(const std::string& filePath);
        static std::string getDirectory(const std::string& filePath);
        
        // Read/Write operations
        static OperationResult readFile(const std::string& filePath, ByteVector& data);
        static OperationResult writeFile(const std::string& filePath, const ByteVector& data);
        static OperationResult readTextFile(const std::string& filePath, std::string& content);
        static OperationResult writeTextFile(const std::string& filePath, const std::string& content);
        
        // Binary file operations
        static OperationResult readBinaryFile(const std::string& filePath, ByteVector& data);
        static OperationResult writeBinaryFile(const std::string& filePath, const ByteVector& data);
        
        // Directory operations
        static bool createDirectory(const std::string& dirPath);
        static bool directoryExists(const std::string& dirPath);
        static std::vector<std::string> listDirectory(const std::string& dirPath);
        static bool removeDirectory(const std::string& dirPath);
        
        // File system utilities
        static std::string getCurrentDirectory();
        static std::string getAbsolutePath(const std::string& relativePath);
        static bool createBackup(const std::string& filePath, const std::string& backupSuffix = ".bak");
        
        // Secure file operations
        static OperationResult secureDelete(const std::string& filePath);
        static OperationResult moveFile(const std::string& source, const std::string& destination);
        static OperationResult copyFile(const std::string& source, const std::string& destination);
        
        // File validation
        static bool isValidPath(const std::string& path);
        static bool hasWritePermission(const std::string& dirPath);
        static bool hasReadPermission(const std::string& filePath);
        
    private:
        static void overwriteFile(const std::string& filePath, size_t fileSize);
    };

} // namespace CryptoApp

#endif // FILE_MANAGER_H
