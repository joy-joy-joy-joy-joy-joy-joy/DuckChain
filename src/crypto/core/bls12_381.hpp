#pragma once

#include <array>
#include <vector>
#include <string>
#include <optional>
#include "crypto/utils/crypto_utils.hpp"

namespace duckchain {
namespace crypto {

/**
 * @brief BLS12-381签名算法实现
 * 
 * BLS12-381是以太坊2.0使用的椭圆曲线
 * - 支持签名聚合
 * - 支持公钥聚合
 * - 支持阈值签名
 * - 抗量子攻击性能良好
 */
class BLS12_381 {
public:
    // ========== 类型定义 ==========
    using PrivateKey = std::array<uint8_t, 32>;     // 32字节私钥
    using PublicKey = std::array<uint8_t, 48>;      // 48字节G1公钥
    using Signature = std::array<uint8_t, 96>;      // 96字节G2签名
    using Message = std::vector<uint8_t>;           // 任意长度消息
    
    // ========== 构造/析构 ==========
    BLS12_381() = default;
    ~BLS12_381() = default;
    
    // 禁用拷贝
    BLS12_381(const BLS12_381&) = delete;
    BLS12_381& operator=(const BLS12_381&) = delete;

    // ========== 密钥生成 ==========
    
    /**
     * @brief 生成随机私钥
     */
    bool generate_private_key(PrivateKey& private_key);
    
    /**
     * @brief 从私钥推导公钥
     */
    bool derive_public_key(PublicKey& public_key, const PrivateKey& private_key);
    
    /**
     * @brief 从种子生成确定性密钥对
     */
    bool keypair_from_seed(PrivateKey& private_key, PublicKey& public_key, const std::vector<uint8_t>& seed);

    // ========== 基础签名/验证 ==========
    
    /**
     * @brief BLS签名
     */
    bool sign(Signature& signature, const Message& message, const PrivateKey& private_key);
    
    /**
     * @brief BLS验证
     */
    bool verify(const Signature& signature, const Message& message, const PublicKey& public_key);

    // ========== 聚合签名 ==========
    
    /**
     * @brief 聚合多个签名
     */
    bool aggregate_signatures(Signature& aggregated_signature, const std::vector<Signature>& signatures);
    
    /**
     * @brief 聚合多个公钥
     */
    bool aggregate_public_keys(PublicKey& aggregated_key, const std::vector<PublicKey>& public_keys);
    
    /**
     * @brief 验证聚合签名（相同消息）
     */
    bool verify_aggregated_same_message(const Signature& aggregated_signature, 
                                       const Message& message,
                                       const std::vector<PublicKey>& public_keys);
    
    /**
     * @brief 验证聚合签名（不同消息）
     */
    bool verify_aggregated_different_messages(const Signature& aggregated_signature,
                                             const std::vector<Message>& messages,
                                             const std::vector<PublicKey>& public_keys);

    // ========== 高级功能 ==========
    
    /**
     * @brief 阈值签名验证（M-of-N）
     */
    bool verify_threshold_signature(const std::vector<Signature>& signatures,
                                   const Message& message,
                                   const std::vector<PublicKey>& public_keys,
                                   size_t threshold);
    
    /**
     * @brief 批量验证（多个独立签名）
     */
    bool batch_verify(const std::vector<Signature>& signatures,
                     const std::vector<Message>& messages,
                     const std::vector<PublicKey>& public_keys);

    // ========== 序列化/反序列化 ==========
    
    std::string private_key_to_hex(const PrivateKey& key);
    std::string public_key_to_hex(const PublicKey& key);
    std::string signature_to_hex(const Signature& sig);
    
    bool private_key_from_hex(PrivateKey& key, const std::string& hex);
    bool public_key_from_hex(PublicKey& key, const std::string& hex);
    bool signature_from_hex(Signature& sig, const std::string& hex);
    
    std::string private_key_to_base64(const PrivateKey& key);
    std::string public_key_to_base64(const PublicKey& key);
    std::string signature_to_base64(const Signature& sig);
    
    bool private_key_from_base64(PrivateKey& key, const std::string& base64);
    bool public_key_from_base64(PublicKey& key, const std::string& base64);
    bool signature_from_base64(Signature& sig, const std::string& base64);

    // ========== 验证和工具 ==========
    
    /**
     * @brief 验证密钥有效性
     */
    bool is_valid_private_key(const PrivateKey& private_key);
    bool is_valid_public_key(const PublicKey& public_key);
    bool is_valid_signature(const Signature& signature);
    
    /**
     * @brief 压缩/解压缩公钥
     */
    bool compress_public_key(std::array<uint8_t, 48>& compressed, const PublicKey& uncompressed);
    bool decompress_public_key(PublicKey& uncompressed, const std::array<uint8_t, 48>& compressed);

    // ========== 错误处理 ==========
    
    std::string get_last_error() const { return last_error_; }
    void clear_error() { last_error_.clear(); }

    // ========== 性能统计 ==========
    
    struct Statistics {
        uint64_t keys_generated = 0;
        uint64_t signatures_created = 0;
        uint64_t signatures_verified = 0;
        uint64_t signatures_aggregated = 0;
        uint64_t public_keys_aggregated = 0;
        double total_sign_time_ms = 0.0;
        double total_verify_time_ms = 0.0;
        double total_aggregate_time_ms = 0.0;
        
        double average_sign_time_ms() const {
            return signatures_created > 0 ? total_sign_time_ms / signatures_created : 0.0;
        }
        double average_verify_time_ms() const {
            return signatures_verified > 0 ? total_verify_time_ms / signatures_verified : 0.0;
        }
        double average_aggregate_time_ms() const {
            return signatures_aggregated > 0 ? total_aggregate_time_ms / signatures_aggregated : 0.0;
        }
    };
    
    Statistics get_statistics() const { return stats_; }
    void reset_statistics() { stats_ = Statistics{}; }

private:
    mutable std::string last_error_;
    mutable Statistics stats_;
    
    void set_error(const std::string& error) const { last_error_ = error; }
    void record_sign_time(double time_ms) const;
    void record_verify_time(double time_ms) const;
    void record_aggregate_time(double time_ms) const;
    void increment_key_count() const { ++stats_.keys_generated; }
    void increment_sign_count() const { ++stats_.signatures_created; }
    void increment_verify_count() const { ++stats_.signatures_verified; }
    void increment_aggregate_count() const { ++stats_.signatures_aggregated; }
    void increment_pubkey_aggregate_count() const { ++stats_.public_keys_aggregated; }
};

} // namespace crypto
} // namespace duckchain 