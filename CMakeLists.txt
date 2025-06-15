cmake_minimum_required(VERSION 3.20)
project(duckchain 
    VERSION 0.1.0
    DESCRIPTION "DuckChain Implementation"
    LANGUAGES CXX
)

# 编译选项
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 项目选项
option(BUILD_TESTS "Build tests" ON)
option(BUILD_BENCHMARKS "Build benchmarks" ON)

# 依赖管理
Include(FetchContent)

# OpenSSL
find_package(OpenSSL REQUIRED)

# GTest
if(BUILD_TESTS)
    FetchContent_Declare(
        GTest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    FetchContent_MakeAvailable(GTest)
    enable_testing()
endif()

# 添加子目录
add_subdirectory(src/crypto)
if(BUILD_TESTS)
    add_subdirectory(test/crypto)
endif()

# 安装规则
include(GNUInstallDirs)
install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
) 