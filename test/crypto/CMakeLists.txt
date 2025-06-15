# 测试源文件
set(CRYPTO_TEST_SOURCES
    core/secp256k1_test.cpp
    core/ed25519_test.cpp
)

# 创建测试可执行文件
add_executable(crypto_tests ${CRYPTO_TEST_SOURCES})

# 设置包含目录
target_include_directories(crypto_tests
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

# 链接依赖
target_link_libraries(crypto_tests
    PRIVATE
        duckchain_crypto
        GTest::gtest
        GTest::gtest_main
)

# 添加测试
add_test(
    NAME crypto_tests
    COMMAND crypto_tests
)

# 添加性能测试
if(BUILD_BENCHMARKS)
    target_compile_definitions(crypto_tests 
        PRIVATE 
        ENABLE_BENCHMARKS
    )
endif()

# 设置测试属性
set_tests_properties(crypto_tests PROPERTIES
    ENVIRONMENT "GTEST_COLOR=1"  # 启用彩色输出
    TIMEOUT 120                  # 设置超时时间（秒）
) 