cmake_minimum_required(VERSION 3.10)
project(transientecc)

set(CMAKE_CXX_STANDARD 17)

# Include your headers
include_directories(include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Source files
file(GLOB SOURCES
    src/*.cpp
)

# Main executable
add_executable(transientecc ${SOURCES})
target_link_libraries(transientecc OpenSSL::SSL OpenSSL::Crypto)

# GoogleTest + Unit Test Support
include(CTest)  # Enables 'make test' / ctest
enable_testing()

# Optional: Add GoogleTest as a submodule (you must clone it in tests/gtest)
add_subdirectory(tests)