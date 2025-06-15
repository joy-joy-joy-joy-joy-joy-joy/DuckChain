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
using Ed25519PrivateKey = std::array<uint8_t, 32>;
using Ed25519PublicKey = std::array<uint8_t, 32>;  // Ed25519 公钥是32字节
using Ed25519Signature = std::array<uint8_t, 64>;  // Ed25519 签名是64字节
using Ed25519Address = std::array<uint8_t, 20>;    // 20字节地址（与以太坊兼容）
using Bytes = std::vector<uint8_t>;

class Ed25519 {
public:
    // 构造和析构
    Ed25519();
    ~Ed25519();

    // 禁用拷贝
    Ed25519(const Ed25519&) = delete;
    Ed25519& operator=(const Ed25519&) = delete;

    // 基本操作
    std::optional<std::pair<Ed25519PrivateKey, Ed25519PublicKey>> generateKeyPair() noexcept;
    std::optional<Ed25519PublicKey> derivePublicKey(const Ed25519PrivateKey& privateKey) noexcept;
    
    // 签名操作
    std::optional<Ed25519Signature> sign(const Bytes& message, const Ed25519PrivateKey& privateKey) noexcept;
    bool verify(const Bytes& message, const Ed25519Signature& signature, const Ed25519PublicKey& publicKey) noexcept;

    // 地址生成
    std::optional<Ed25519Address> deriveAddress(const Ed25519PublicKey& publicKey) noexcept;
    
    // 错误信息
    std::string getLastError() const noexcept { return last_error_; }

private:
    // 错误处理
    std::string last_error_;
    void setError(const std::string& error) noexcept { last_error_ = error; }
};

} // namespace crypto
} // namespace duckchain 