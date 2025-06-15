#pragma once

#include <vector>
#include <array>
#include <optional>
#include <string>
#include <cstdint>
#include <utility>

namespace duckchain {
namespace crypto {

// 基础类型定义
using Bytes = std::vector<uint8_t>;
using PrivateKey = std::array<uint8_t, 32>;
using PublicKey = std::array<uint8_t, 33>;  // 压缩格式
using Signature = std::array<uint8_t, 64>;   // r(32) + s(32)

class Secp256k1 {
public:
    // 构造和析构
    Secp256k1();
    ~Secp256k1();

    // 禁用拷贝
    Secp256k1(const Secp256k1&) = delete;
    Secp256k1& operator=(const Secp256k1&) = delete;

    // 基本操作
    std::optional<std::pair<PrivateKey, PublicKey>> generateKeyPair() noexcept;
    std::optional<PublicKey> derivePublicKey(const PrivateKey& privateKey) noexcept;
    
    // 签名操作
    std::optional<Signature> sign(const Bytes& message, const PrivateKey& privateKey) noexcept;
    bool verify(const Bytes& message, const Signature& signature, const PublicKey& publicKey) noexcept;

    // 地址生成
    std::optional<std::array<uint8_t, 20>> deriveAddress(const PublicKey& publicKey) noexcept;
    
    // 错误信息
    std::string getLastError() const noexcept { return last_error_; }

private:
    // 错误处理
    std::string last_error_;
    void setError(const std::string& error) noexcept { last_error_ = error; }
};

} // namespace crypto
} // namespace duckchain 