enable_testing()
add_subdirectory(gtest)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

add_executable(runTests test_obfuscator.cpp)
target_link_libraries(runTests gtest gtest_main OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME runTests COMMAND runTests)