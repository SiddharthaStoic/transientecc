cmake_minimum_required(VERSION 3.10)
project(transientecc)

set(CMAKE_CXX_STANDARD 17)

# Include your headers
include_directories(include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Main executable (only includes files needed by main.cpp)
add_executable(transientecc
    src/main.cpp
    src/keygen.cpp
    src/curve_pool.cpp
    src/obfuscator.cpp
)
target_link_libraries(transientecc OpenSSL::SSL OpenSSL::Crypto)

# ECDH demo executable (includes new ECDHSession module)
add_executable(ecdh_demo
    src/ecdh_demo.cpp
    src/ECDHSession.cpp
    src/curve_pool.cpp
    src/obfuscator.cpp
)
target_link_libraries(ecdh_demo OpenSSL::SSL OpenSSL::Crypto)

# AES demo executable
add_executable(aes_demo
    src/aes_demo.cpp
    src/AESGCM.cpp
    src/ECDHSession.cpp
    src/obfuscator.cpp
    src/curve_pool.cpp
)

target_link_libraries(aes_demo OpenSSL::SSL OpenSSL::Crypto)

# Benchmark executable
add_executable(benchmark
    src/benchmark.cpp
    src/ECDHSession.cpp
    src/curve_pool.cpp
    src/obfuscator.cpp
)
target_link_libraries(benchmark OpenSSL::SSL OpenSSL::Crypto)


# GoogleTest + Unit Test Support
include(CTest)
enable_testing()
add_subdirectory(tests)