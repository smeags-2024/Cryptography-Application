#include "utils/file_manager.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <random>
#include <algorithm>

namespace fs = boost::filesystem;

namespace CryptoApp {

FileManager::FileManager() {}

FileManager::~FileManager() {}

bool FileManager::fileExists(const std::string& filePath) {
    return fs::exists(filePath) && fs::is_regular_file(filePath);
}

size_t FileManager::getFileSize(const std::string& filePath) {
    if (!fileExists(filePath)) {
        return 0;
    }
    return fs::file_size(filePath);
}

FileType FileManager::detectFileType(const std::string& filePath) {
    if (!fileExists(filePath)) {
        return FileType::UNKNOWN;
    }
    
    std::string extension = getFileExtension(filePath);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    // Text file extensions
    std::vector<std::string> textExtensions = {
        ".txt", ".log", ".conf", ".ini", ".cfg", ".xml", ".json", ".csv",
        ".c", ".cpp", ".h", ".hpp", ".py", ".java", ".js", ".html", ".css"
    };
    
    for (const auto& ext : textExtensions) {
        if (extension == ext) {
            return FileType::TEXT;
        }
    }
    
    return FileType::BINARY;
}

std::string FileManager::getFileExtension(const std::string& filePath) {
    fs::path path(filePath);
    return path.extension().string();
}

std::string FileManager::getFileName(const std::string& filePath) {
    fs::path path(filePath);
    return path.filename().string();
}

std::string FileManager::getDirectory(const std::string& filePath) {
    fs::path path(filePath);
    return path.parent_path().string();
}

OperationResult FileManager::readFile(const std::string& filePath, ByteVector& data) {
    return readBinaryFile(filePath, data);
}

OperationResult FileManager::writeFile(const std::string& filePath, const ByteVector& data) {
    return writeBinaryFile(filePath, data);
}

OperationResult FileManager::readTextFile(const std::string& filePath, std::string& content) {
    try {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            return OperationResult(false, "Cannot open file for reading: " + filePath);
        }
        
        content.assign((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
        file.close();
        
        return OperationResult(true, "File read successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Error reading file: ") + e.what());
    }
}

OperationResult FileManager::writeTextFile(const std::string& filePath, const std::string& content) {
    try {
        // Create directory if it doesn't exist
        fs::path path(filePath);
        fs::path dir = path.parent_path();
        if (!dir.empty() && !fs::exists(dir)) {
            fs::create_directories(dir);
        }
        
        std::ofstream file(filePath);
        if (!file.is_open()) {
            return OperationResult(false, "Cannot open file for writing: " + filePath);
        }
        
        file << content;
        file.close();
        
        return OperationResult(true, "File written successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Error writing file: ") + e.what());
    }
}

OperationResult FileManager::readBinaryFile(const std::string& filePath, ByteVector& data) {
    try {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return OperationResult(false, "Cannot open file for reading: " + filePath);
        }
        
        // Get file size
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // Read file content
        data.resize(fileSize);
        file.read(reinterpret_cast<char*>(data.data()), fileSize);
        file.close();
        
        return OperationResult(true, "Binary file read successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Error reading binary file: ") + e.what());
    }
}

OperationResult FileManager::writeBinaryFile(const std::string& filePath, const ByteVector& data) {
    try {
        // Create directory if it doesn't exist
        fs::path path(filePath);
        fs::path dir = path.parent_path();
        if (!dir.empty() && !fs::exists(dir)) {
            fs::create_directories(dir);
        }
        
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return OperationResult(false, "Cannot open file for writing: " + filePath);
        }
        
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        
        return OperationResult(true, "Binary file written successfully");
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Error writing binary file: ") + e.what());
    }
}

bool FileManager::createDirectory(const std::string& dirPath) {
    try {
        return fs::create_directories(dirPath);
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

bool FileManager::directoryExists(const std::string& dirPath) {
    return fs::exists(dirPath) && fs::is_directory(dirPath);
}

std::vector<std::string> FileManager::listDirectory(const std::string& dirPath) {
    std::vector<std::string> files;
    
    try {
        if (fs::exists(dirPath) && fs::is_directory(dirPath)) {
            for (const auto& entry : fs::directory_iterator(dirPath)) {
                files.push_back(entry.path().string());
            }
        }
    } catch (const fs::filesystem_error&) {
        // Return empty vector on error
    }
    
    return files;
}

bool FileManager::removeDirectory(const std::string& dirPath) {
    try {
        return fs::remove_all(dirPath) > 0;
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

std::string FileManager::getCurrentDirectory() {
    try {
        return fs::current_path().string();
    } catch (const fs::filesystem_error&) {
        return "";
    }
}

std::string FileManager::getAbsolutePath(const std::string& relativePath) {
    try {
        return fs::absolute(relativePath).string();
    } catch (const fs::filesystem_error&) {
        return relativePath;
    }
}

bool FileManager::createBackup(const std::string& filePath, const std::string& backupSuffix) {
    if (!fileExists(filePath)) {
        return false;
    }
    
    std::string backupPath = filePath + backupSuffix;
    auto result = copyFile(filePath, backupPath);
    return result.success;
}

OperationResult FileManager::secureDelete(const std::string& filePath) {
    if (!fileExists(filePath)) {
        return OperationResult(false, "File does not exist: " + filePath);
    }
    
    try {
        size_t fileSize = getFileSize(filePath);
        
        // Overwrite file multiple times with random data
        overwriteFile(filePath, fileSize);
        overwriteFile(filePath, fileSize);
        overwriteFile(filePath, fileSize);
        
        // Finally remove the file
        if (fs::remove(filePath)) {
            return OperationResult(true, "File securely deleted");
        } else {
            return OperationResult(false, "Failed to remove file after overwriting");
        }
        
    } catch (const std::exception& e) {
        return OperationResult(false, std::string("Error during secure delete: ") + e.what());
    }
}

OperationResult FileManager::moveFile(const std::string& source, const std::string& destination) {
    try {
        // Create destination directory if it doesn't exist
        fs::path destPath(destination);
        fs::path destDir = destPath.parent_path();
        if (!destDir.empty() && !fs::exists(destDir)) {
            fs::create_directories(destDir);
        }
        
        fs::rename(source, destination);
        return OperationResult(true, "File moved successfully");
        
    } catch (const fs::filesystem_error& e) {
        return OperationResult(false, std::string("Error moving file: ") + e.what());
    }
}

OperationResult FileManager::copyFile(const std::string& source, const std::string& destination) {
    try {
        // Create destination directory if it doesn't exist
        fs::path destPath(destination);
        fs::path destDir = destPath.parent_path();
        if (!destDir.empty() && !fs::exists(destDir)) {
            fs::create_directories(destDir);
        }
        
        fs::copy_file(source, destination, fs::copy_options::overwrite_existing);
        return OperationResult(true, "File copied successfully");
        
    } catch (const fs::filesystem_error& e) {
        return OperationResult(false, std::string("Error copying file: ") + e.what());
    }
}

bool FileManager::isValidPath(const std::string& path) {
    try {
        fs::path p(path);
        return !path.empty() && (p.is_absolute() || p.is_relative());
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

bool FileManager::hasWritePermission(const std::string& dirPath) {
    try {
        if (!directoryExists(dirPath)) {
            return false;
        }
        
        // Try to create a temporary file
        std::string tempFile = dirPath + "/temp_permission_test";
        std::ofstream test(tempFile);
        if (test.is_open()) {
            test.close();
            fs::remove(tempFile);
            return true;
        }
        return false;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool FileManager::hasReadPermission(const std::string& filePath) {
    try {
        std::ifstream test(filePath);
        return test.is_open();
    } catch (const std::exception&) {
        return false;
    }
}

void FileManager::overwriteFile(const std::string& filePath, size_t fileSize) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::ofstream file(filePath, std::ios::binary);
    if (file.is_open()) {
        for (size_t i = 0; i < fileSize; ++i) {
            unsigned char randomByte = static_cast<unsigned char>(dis(gen));
            file.write(reinterpret_cast<const char*>(&randomByte), 1);
        }
        file.close();
    }
}

} // namespace CryptoApp
