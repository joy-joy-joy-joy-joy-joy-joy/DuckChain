#pragma once

#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <optional>

namespace duckchain {
namespace crypto {
namespace utils {

// ========== 基础类型定义 ==========
using Bytes = std::vector<uint8_t>;

// ========== 编码/解码工具 ==========

/**
 * @brief 十六进制编码
 */
std::string to_hex(const std::vector<uint8_t>& data);
std::string to_hex(const uint8_t* data, size_t length);
template<size_t N>
std::string to_hex(const std::array<uint8_t, N>& data);

/**
 * @brief 十六进制解码
 */
bool from_hex(std::vector<uint8_t>& output, const std::string& hex);
template<size_t N>
bool from_hex(std::array<uint8_t, N>& output, const std::string& hex);

/**
 * @brief Base64编码
 */
std::string to_base64(const std::vector<uint8_t>& data);
std::string to_base64(const uint8_t* data, size_t length);

/**
 * @brief Base64解码
 */
bool from_base64(std::vector<uint8_t>& output, const std::string& base64);

// ========== 随机数生成 ==========

/**
 * @brief 安全随机数生成
 */
bool secure_random_bytes(std::vector<uint8_t>& output, size_t length);
bool secure_random_bytes(uint8_t* output, size_t length);
template<size_t N>
bool secure_random_bytes(std::array<uint8_t, N>& output);

uint32_t secure_random_uint32();
uint64_t secure_random_uint64();

// ========== 哈希函数 ==========

/**
 * @brief SHA-256哈希
 */
std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);
std::array<uint8_t, 32> sha256(const uint8_t* data, size_t length);
std::array<uint8_t, 32> sha256(const std::string& data);

/**
 * @brief SHA-512哈希
 */
std::array<uint8_t, 64> sha512(const std::vector<uint8_t>& data);
std::array<uint8_t, 64> sha512(const uint8_t* data, size_t length);

/**
 * @brief BLAKE2b哈希
 */
std::array<uint8_t, 32> blake2b_256(const std::vector<uint8_t>& data);
std::array<uint8_t, 64> blake2b_512(const std::vector<uint8_t>& data);

// ========== 常数时间比较 ==========

/**
 * @brief 常数时间内存比较（防止时序攻击）
 */
bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t length);
template<size_t N>
bool constant_time_equals(const std::array<uint8_t, N>& a, const std::array<uint8_t, N>& b);

// ========== 安全内存管理 ==========

/**
 * @brief 安全清零内存
 */
void secure_zero_memory(void* ptr, size_t size);
void secure_zero_memory(std::vector<uint8_t>& data);
template<size_t N>
void secure_zero_memory(std::array<uint8_t, N>& data);

// ========== 错误处理 ==========

enum class CryptoError {
    SUCCESS = 0,
    INVALID_INPUT,
    INVALID_LENGTH,
    ENCODING_ERROR,
    DECODING_ERROR,
    RANDOM_GENERATION_FAILED,
    HASH_FAILED,
    UNKNOWN_ERROR
};

class CryptoException : public std::exception {
public:
    CryptoException(CryptoError error, const std::string& message)
        : error_(error), message_(message) {}
    
    const char* what() const noexcept override { return message_.c_str(); }
    CryptoError error() const noexcept { return error_; }

private:
    CryptoError error_;
    std::string message_;
};

// ========== 模板实现 ==========

template<size_t N>
std::string to_hex(const std::array<uint8_t, N>& data) {
    return to_hex(data.data(), data.size());
}

template<size_t N>
bool from_hex(std::array<uint8_t, N>& output, const std::string& hex) {
    std::vector<uint8_t> temp;
    if (!from_hex(temp, hex) || temp.size() != N) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), output.begin());
    return true;
}

template<size_t N>
bool secure_random_bytes(std::array<uint8_t, N>& output) {
    return secure_random_bytes(output.data(), output.size());
}

template<size_t N>
bool constant_time_equals(const std::array<uint8_t, N>& a, const std::array<uint8_t, N>& b) {
    return constant_time_equals(a.data(), b.data(), a.size());
}

template<size_t N>
void secure_zero_memory(std::array<uint8_t, N>& data) {
    secure_zero_memory(data.data(), data.size());
}

} // namespace utils
} // namespace crypto
} // namespace duckchain 