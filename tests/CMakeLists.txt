enable_testing()
add_subdirectory(gtest)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

# Only link to logic files — avoid anything with `main()`
add_executable(runTests
    test_obfuscator.cpp
    ../src/obfuscator.cpp
    ../src/curve_pool.cpp
)

target_link_libraries(runTests gtest gtest_main OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME runTests COMMAND runTests)