# 源文件
set(CRYPTO_SOURCES
    core/secp256k1.cpp
    core/ed25519.cpp
)

set(CRYPTO_HEADERS
    core/secp256k1.hpp
    core/ed25519.hpp
)

# 创建加密库
add_library(duckchain_crypto STATIC
    ${CRYPTO_SOURCES}
    ${CRYPTO_HEADERS}
)

# 设置包含目录
target_include_directories(duckchain_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

# 设置库属性
set_target_properties(duckchain_crypto PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    EXPORT_NAME Crypto
)

# 链接依赖
target_link_libraries(duckchain_crypto
    PRIVATE
        OpenSSL::Crypto
)

# 安装规则
install(TARGETS duckchain_crypto
    EXPORT ${PROJECT_NAME}Targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES ${CRYPTO_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto/core
) 