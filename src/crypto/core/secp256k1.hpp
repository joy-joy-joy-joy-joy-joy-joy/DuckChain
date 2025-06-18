#pragma once

#include <array>
#include <vector>
#include <string>
#include <optional>
#include "crypto/utils/crypto_utils.hpp"

namespace duckchain {
namespace crypto {

/**
 * @brief secp256k1椭圆曲线数字签名算法实现
 */
class Secp256k1 {
public:
    // ========== 类型定义 ==========
    using PrivateKey = std::array<uint8_t, 32>;     // 32字节私钥
    using PublicKey = std::array<uint8_t, 33>;      // 33字节压缩公钥
    using Signature = std::array<uint8_t, 64>;      // 64字节紧凑签名
    using Message = std::vector<uint8_t>;           // 任意长度消息
    using Hash = std::array<uint8_t, 32>;           // 32字节哈希
    
    // ========== 构造/析构 ==========
    Secp256k1();
    ~Secp256k1();
    
    // 禁用拷贝
    Secp256k1(const Secp256k1&) = delete;
    Secp256k1& operator=(const Secp256k1&) = delete;

    // ========== 密钥生成 ==========
    
    /**
     * @brief 生成随机私钥
     */
    bool generate_private_key(PrivateKey& private_key);
    
    /**
     * @brief 从私钥推导公钥
     */
    bool derive_public_key(PublicKey& public_key, const PrivateKey& private_key);

    // ========== ECDSA签名/验证 ==========
    
    /**
     * @brief ECDSA签名（基于消息哈希）
     */
    bool sign_ecdsa(Signature& signature, const Hash& message_hash, const PrivateKey& private_key);
    
    /**
     * @brief ECDSA验证
     */
    bool verify_ecdsa(const Signature& signature, const Hash& message_hash, const PublicKey& public_key);

    // ========== 序列化/反序列化 ==========
    
    std::string private_key_to_hex(const PrivateKey& key);
    std::string public_key_to_hex(const PublicKey& key);
    std::string signature_to_hex(const Signature& sig);
    
    bool private_key_from_hex(PrivateKey& key, const std::string& hex);
    bool public_key_from_hex(PublicKey& key, const std::string& hex);
    bool signature_from_hex(Signature& sig, const std::string& hex);

    // ========== 验证和工具 ==========
    
    /**
     * @brief 验证密钥有效性
     */
    bool is_valid_private_key(const PrivateKey& private_key);
    bool is_valid_public_key(const PublicKey& public_key);
    
    /**
     * @brief 生成消息哈希
     */
    Hash hash_message(const Message& message);

    // ========== 错误处理 ==========
    
    std::string get_last_error() const { return last_error_; }
    void clear_error() { last_error_.clear(); }

    // ========== 性能统计 ==========
    
    struct Statistics {
        uint64_t keys_generated = 0;
        uint64_t signatures_created = 0;
        uint64_t signatures_verified = 0;
        double total_sign_time_ms = 0.0;
        double total_verify_time_ms = 0.0;
        
        double average_sign_time_ms() const {
            return signatures_created > 0 ? total_sign_time_ms / signatures_created : 0.0;
        }
        double average_verify_time_ms() const {
            return signatures_verified > 0 ? total_verify_time_ms / signatures_verified : 0.0;
        }
    };
    
    Statistics get_statistics() const { return stats_; }
    void reset_statistics() { stats_ = Statistics{}; }

private:
    void* context_;  // secp256k1_context*
    mutable std::string last_error_;
    mutable Statistics stats_;
    
    void set_error(const std::string& error) const { last_error_ = error; }
    void record_sign_time(double time_ms) const;
    void record_verify_time(double time_ms) const;
    void increment_key_count() const { ++stats_.keys_generated; }
    void increment_sign_count() const { ++stats_.signatures_created; }
    void increment_verify_count() const { ++stats_.signatures_verified; }
};

} // namespace crypto
} // namespace duckchain 