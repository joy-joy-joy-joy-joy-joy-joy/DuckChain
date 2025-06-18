#include "crypto/utils/crypto_utils.hpp"
#include <sodium.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <mutex>

namespace duckchain {
namespace crypto {
namespace utils {

// 线程安全的libsodium初始化
static std::once_flag sodium_init_flag;

void ensure_sodium_init() {
    std::call_once(sodium_init_flag, []() {
        if (sodium_init() < 0) {
            throw CryptoException(CryptoError::UNKNOWN_ERROR, "Failed to initialize libsodium");
        }
    });
}

// ========== 十六进制编码/解码 ==========

std::string to_hex(const std::vector<uint8_t>& data) {
    return to_hex(data.data(), data.size());
}

std::string to_hex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

bool from_hex(std::vector<uint8_t>& output, const std::string& hex) {
    if (hex.length() % 2 != 0) {
        return false;
    }
    
    output.clear();
    output.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        char c1 = hex[i];
        char c2 = hex[i + 1];
        
        // 检查字符是否为有效的十六进制字符
        auto is_hex_char = [](char c) {
            return (c >= '0' && c <= '9') || 
                   (c >= 'a' && c <= 'f') || 
                   (c >= 'A' && c <= 'F');
        };
        
        if (!is_hex_char(c1) || !is_hex_char(c2)) {
            return false;
        }
        
        // 转换十六进制字符到数值
        auto hex_to_int = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;  // 这里不会到达
        };
        
        uint8_t byte = (hex_to_int(c1) << 4) | hex_to_int(c2);
        output.push_back(byte);
    }
    
    return true;
}

// ========== Base64编码/解码 ==========

std::string to_base64(const std::vector<uint8_t>& data) {
    return to_base64(data.data(), data.size());
}

std::string to_base64(const uint8_t* data, size_t length) {
    ensure_sodium_init();
    
    const size_t base64_maxlen = sodium_base64_encoded_len(length, sodium_base64_VARIANT_ORIGINAL);
    std::string base64(base64_maxlen, '\0');
    
    sodium_bin2base64(base64.data(), base64.size(), data, length, 
                     sodium_base64_VARIANT_ORIGINAL);
    
    // 移除null终止符
    if (!base64.empty() && base64.back() == '\0') {
        base64.pop_back();
    }
    return base64;
}

bool from_base64(std::vector<uint8_t>& output, const std::string& base64) {
    ensure_sodium_init();
    
    output.resize(base64.length());  // 最大可能的大小
    size_t bin_len;
    
    if (sodium_base642bin(output.data(), output.size(), base64.c_str(), base64.size(),
                         nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        return false;
    }
    
    output.resize(bin_len);
    return true;
}

// ========== 随机数生成 ==========

bool secure_random_bytes(std::vector<uint8_t>& output, size_t length) {
    output.resize(length);
    return secure_random_bytes(output.data(), length);
}

bool secure_random_bytes(uint8_t* output, size_t length) {
    ensure_sodium_init();
    randombytes_buf(output, length);
    return true;
}

uint32_t secure_random_uint32() {
    ensure_sodium_init();
    return randombytes_random();
}

uint64_t secure_random_uint64() {
    uint64_t result;
    secure_random_bytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

// ========== 哈希函数 ==========

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t length) {
    ensure_sodium_init();
    std::array<uint8_t, 32> hash;
    crypto_hash_sha256(hash.data(), data, length);
    return hash;
}

std::array<uint8_t, 32> sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, 64> sha512(const std::vector<uint8_t>& data) {
    return sha512(data.data(), data.size());
}

std::array<uint8_t, 64> sha512(const uint8_t* data, size_t length) {
    ensure_sodium_init();
    std::array<uint8_t, 64> hash;
    crypto_hash_sha512(hash.data(), data, length);
    return hash;
}

std::array<uint8_t, 32> blake2b_256(const std::vector<uint8_t>& data) {
    ensure_sodium_init();
    std::array<uint8_t, 32> hash;
    crypto_generichash_blake2b(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);
    return hash;
}

std::array<uint8_t, 64> blake2b_512(const std::vector<uint8_t>& data) {
    ensure_sodium_init();
    std::array<uint8_t, 64> hash;
    crypto_generichash_blake2b(hash.data(), hash.size(), data.data(), data.size(), nullptr, 0);
    return hash;
}

// ========== 常数时间比较 ==========

bool constant_time_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return constant_time_equals(a.data(), b.data(), a.size());
}

bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t length) {
    ensure_sodium_init();
    return sodium_memcmp(a, b, length) == 0;
}

// ========== 安全内存管理 ==========

void secure_zero_memory(void* ptr, size_t size) {
    ensure_sodium_init();
    sodium_memzero(ptr, size);
}

void secure_zero_memory(std::vector<uint8_t>& data) {
    secure_zero_memory(data.data(), data.size());
}

} // namespace utils
} // namespace crypto
} // namespace duckchain 