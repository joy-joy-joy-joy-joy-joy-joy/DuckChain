#pragma once

#include <array>
#include <vector>
#include <string>
#include <atomic>
#include "crypto/utils/crypto_utils.hpp"

namespace duckchain {
namespace crypto {

/**
 * @brief Ed25519签名算法实现
 * 
 * Ed25519是一个高性能的椭圆曲线数字签名算法
 * - 快速签名和验证
 * - 小的密钥和签名尺寸
 * - 抗侧信道攻击
 * - 确定性签名
 * 
 * 线程安全: 所有成员函数都是线程安全的
 */
class Ed25519 {
public:
    // ========== 类型定义 ==========
    using PrivateKey = std::array<uint8_t, 32>;    // 32字节私钥
    using PublicKey = std::array<uint8_t, 32>;     // 32字节公钥
    using Signature = std::array<uint8_t, 64>;     // 64字节签名
    using Seed = std::array<uint8_t, 32>;          // 32字节种子
    using Message = std::vector<uint8_t>;          // 任意长度消息
    
    // ========== 构造/析构 ==========
    Ed25519() = default;
    ~Ed25519() = default;
    
    // 禁用拷贝
    Ed25519(const Ed25519&) = delete;
    Ed25519& operator=(const Ed25519&) = delete;

    // ========== 密钥生成 ==========
    
    /**
     * @brief 生成密钥对
     */
    bool generate_keypair(PrivateKey& private_key, PublicKey& public_key);
    
    /**
     * @brief 从种子生成密钥对（确定性）
     */
    bool keypair_from_seed(PrivateKey& private_key, PublicKey& public_key, const Seed& seed);
    
    /**
     * @brief 从私钥推导公钥
     */
    bool derive_public_key(PublicKey& public_key, const PrivateKey& private_key);

    // ========== 签名/验证 ==========
    
    /**
     * @brief 对消息进行签名
     */
    bool sign(Signature& signature, const Message& message, const PrivateKey& private_key);
    
    /**
     * @brief 验证签名
     */
    bool verify(const Signature& signature, const Message& message, const PublicKey& public_key);
    
    // ========== 验证和工具 ==========
    
    /**
     * @brief 验证密钥有效性
     */
    static bool is_valid_private_key(const PrivateKey& private_key);
    static bool is_valid_public_key(const PublicKey& public_key);
    static bool is_valid_signature(const Signature& signature);
    
    /**
     * @brief 生成随机种子
     */
    bool generate_seed(Seed& seed);

    // ========== 序列化/反序列化 ==========
    
    std::string private_key_to_hex(const PrivateKey& key);
    std::string public_key_to_hex(const PublicKey& key);
    std::string signature_to_hex(const Signature& sig);
    std::string seed_to_hex(const Seed& seed);
    
    bool private_key_from_hex(PrivateKey& key, const std::string& hex);
    bool public_key_from_hex(PublicKey& key, const std::string& hex);
    bool signature_from_hex(Signature& sig, const std::string& hex);
    bool seed_from_hex(Seed& seed, const std::string& hex);
    
    // Base64 encoding/decoding
    std::string private_key_to_base64(const PrivateKey& key);
    std::string public_key_to_base64(const PublicKey& key);
    std::string signature_to_base64(const Signature& sig);
    bool private_key_from_base64(PrivateKey& key, const std::string& base64);
    bool public_key_from_base64(PublicKey& key, const std::string& base64);
    bool signature_from_base64(Signature& sig, const std::string& base64);

    // Detached signatures
    bool sign_detached(Signature& signature, const Message& message, const PrivateKey& private_key);
    bool verify_detached(const Signature& signature, const Message& message, const PublicKey& public_key);

    // Multi-signature support
    bool aggregate_public_keys(PublicKey& aggregated_key, const std::vector<PublicKey>& public_keys);
    bool verify_multisig(const std::vector<Signature>& signatures,
                        const Message& message,
                        const std::vector<PublicKey>& public_keys,
                        size_t threshold);

    // ========== 性能统计（线程安全） ==========
    
    struct Statistics {
        std::atomic<uint64_t> keypairs_generated{0};
        std::atomic<uint64_t> signatures_created{0};
        std::atomic<uint64_t> signatures_verified{0};
        
        uint64_t get_keypairs_generated() const { return keypairs_generated.load(); }
        uint64_t get_signatures_created() const { return signatures_created.load(); }
        uint64_t get_signatures_verified() const { return signatures_verified.load(); }
    };
    
    static Statistics& get_statistics();

private:
    void increment_keypair_count();
    void increment_sign_count();
    void increment_verify_count();
    void record_sign_time(double time_ms) const;
    void record_verify_time(double time_ms) const;
    void set_error(const std::string& error) const;
};

} // namespace crypto
} // namespace duckchain 