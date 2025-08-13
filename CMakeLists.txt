cmake_minimum_required(VERSION 3.16)
project(CryptographyApplication VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem program_options)
find_package(PkgConfig REQUIRED)

# Find Crypto++
find_library(CRYPTOPP_LIBRARIES cryptopp)
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h)

if(NOT CRYPTOPP_LIBRARIES)
    message(FATAL_ERROR "Crypto++ library not found")
endif()

# Find Qt5 for GUI
find_package(Qt5 REQUIRED COMPONENTS Core Widgets)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${CRYPTOPP_INCLUDE_DIR}
)

# Source files
set(SOURCES
    src/main.cpp
    src/cryptography/aes_crypto.cpp
    src/cryptography/rsa_crypto.cpp
    src/cryptography/blowfish_crypto.cpp
    src/cryptography/hash_functions.cpp
    src/cryptography/digital_signature.cpp
    src/storage/secure_storage.cpp
    src/gui/main_window.cpp
    src/gui/encryption_dialog.cpp
    src/gui/decryption_dialog.cpp
    src/gui/signature_dialog.cpp
    src/utils/file_manager.cpp
    src/utils/key_generator.cpp
)

# Header files
set(HEADERS
    include/cryptography/aes_crypto.h
    include/cryptography/rsa_crypto.h
    include/cryptography/blowfish_crypto.h
    include/cryptography/hash_functions.h
    include/cryptography/digital_signature.h
    include/storage/secure_storage.h
    include/gui/main_window.h
    include/gui/encryption_dialog.h
    include/gui/decryption_dialog.h
    include/gui/signature_dialog.h
    include/utils/file_manager.h
    include/utils/key_generator.h
    include/common/types.h
)

# Qt MOC processing
qt5_wrap_cpp(MOC_SOURCES ${HEADERS})

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${MOC_SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${CRYPTOPP_LIBRARIES}
    Qt5::Core
    Qt5::Widgets
)

# Compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -O2
    -fPIC
)

# Install targets
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
