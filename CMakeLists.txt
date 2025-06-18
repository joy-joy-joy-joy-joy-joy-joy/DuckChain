cmake_minimum_required(VERSION 3.16)
project(duckchain VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 编译选项
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 查找系统库
find_package(PkgConfig REQUIRED)

# 1. libsodium (Ed25519和其他现代密码学原语)
pkg_check_modules(SODIUM REQUIRED libsodium)

# 2. blst library (BLS12-381)
set(BLST_ROOT ${CMAKE_SOURCE_DIR}/third_party/blst)
find_library(BLST_LIBRARY 
    NAMES blst
    PATHS ${BLST_ROOT}
    NO_DEFAULT_PATH
    REQUIRED
)

# 3. libsecp256k1 (secp256k1椭圆曲线)
set(SECP256K1_ROOT ${CMAKE_SOURCE_DIR}/third_party/secp256k1)
find_library(SECP256K1_LIBRARY 
    NAMES secp256k1
    PATHS ${SECP256K1_ROOT}/.libs
    NO_DEFAULT_PATH
    REQUIRED
)

# 创建导入的库目标
add_library(blst_imported STATIC IMPORTED)
set_target_properties(blst_imported PROPERTIES
    IMPORTED_LOCATION ${BLST_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_ROOT}/bindings
)

add_library(secp256k1_imported STATIC IMPORTED)
set_target_properties(secp256k1_imported PROPERTIES
    IMPORTED_LOCATION ${SECP256K1_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${SECP256K1_ROOT}/include
)

# 主加密库
add_library(duckchain_crypto STATIC
    src/crypto/utils/crypto_utils.cpp
    src/crypto/core/ed25519.cpp
    src/crypto/core/secp256k1.cpp
    src/crypto/core/bls12_381.cpp
)

target_include_directories(duckchain_crypto
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src
        ${BLST_ROOT}/bindings
        ${SECP256K1_ROOT}/include
        ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(duckchain_crypto
    PUBLIC
        blst_imported
        secp256k1_imported
        ${SODIUM_LIBRARIES}
)

target_compile_options(duckchain_crypto PUBLIC ${SODIUM_CFLAGS_OTHER})

# 测试配置
enable_testing()

# 使用FetchContent下载并构建GoogleTest
include(FetchContent)
    FetchContent_Declare(
    googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )

# 设置gtest选项
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# 创建测试可执行文件
add_executable(crypto_tests
    test/crypto/utils/crypto_utils_test.cpp
    test/crypto/core/ed25519_test.cpp
    test/crypto/core/secp256k1_test.cpp
    test/crypto/core/bls12_381_test.cpp
)

target_link_libraries(crypto_tests
    PRIVATE
        duckchain_crypto
        gtest_main
        gmock_main
)

# 注册测试
include(GoogleTest)
gtest_discover_tests(crypto_tests)

message(STATUS "GoogleTest configured and tests will be built")

# Network library
add_library(duckchain_network
    src/network/core/message.cpp
)

target_include_directories(duckchain_network PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

# Network tests
add_executable(network_tests
    test/network/core/message_test.cpp
)

target_link_libraries(network_tests
    duckchain_network
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME network_tests COMMAND network_tests)

# 输出配置信息
message(STATUS "=== DuckChain Crypto Library Configuration ===")
message(STATUS "blst library: ${BLST_LIBRARY}")
message(STATUS "secp256k1 library: ${SECP256K1_LIBRARY}")
message(STATUS "libsodium version: ${SODIUM_VERSION}")
message(STATUS "libsodium libs: ${SODIUM_LIBRARIES}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "===============================================")

# 安装配置
include(GNUInstallDirs)

install(TARGETS duckchain_crypto
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY src/crypto/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/duckchain/crypto
    FILES_MATCHING PATTERN "*.hpp"
) 