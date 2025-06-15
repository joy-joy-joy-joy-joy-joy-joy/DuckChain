add_library(duckchain_crypto STATIC)

target_sources(duckchain_crypto
    PRIVATE
        secp256k1.cpp
        ed25519.cpp
)

target_include_directories(duckchain_crypto
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
)

find_package(OpenSSL REQUIRED)
target_link_libraries(duckchain_crypto
    PUBLIC
        OpenSSL::Crypto
) 