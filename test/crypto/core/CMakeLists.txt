add_executable(crypto_tests)

target_sources(crypto_tests
    PRIVATE
        secp256k1_test.cpp
        ed25519_test.cpp
)

target_link_libraries(crypto_tests
    PRIVATE
        duckchain_crypto
        GTest::gtest
        GTest::gtest_main
) 