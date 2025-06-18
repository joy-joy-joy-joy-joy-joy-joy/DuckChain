#include "crypto/core/ed25519.hpp"
#include <sodium.h>
#include <chrono>
#include <cstring>

namespace duckchain {
namespace crypto {

using namespace utils;

// 全局统计对象
Ed25519::Statistics& Ed25519::get_statistics() {
    static Statistics stats;
    return stats;
}

void Ed25519::increment_keypair_count() {
    get_statistics().keypairs_generated++;
}

void Ed25519::increment_sign_count() {
    get_statistics().signatures_created++;
}

void Ed25519::increment_verify_count() {
    get_statistics().signatures_verified++;
}

void Ed25519::record_sign_time(double time_ms) const {
    // TODO: Add signing time statistics if needed
}

void Ed25519::record_verify_time(double time_ms) const {
    // TODO: Add verification time statistics if needed
}

void Ed25519::set_error(const std::string& error) const {
    // TODO: Add error handling if needed
}

// ========== 密钥生成 ==========

bool Ed25519::generate_keypair(PrivateKey& private_key, PublicKey& public_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // libsodium的Ed25519密钥生成
        int result = crypto_sign_keypair(public_key.data(), private_key.data());
        
        if (result != 0) {
            set_error("Failed to generate Ed25519 keypair");
            return false;
        }
        
        increment_keypair_count();
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        // 记录密钥生成时间（如果需要的话）
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 keypair generation failed: " + std::string(e.what()));
        return false;
    }
}

bool Ed25519::keypair_from_seed(PrivateKey& private_key, PublicKey& public_key, const Seed& seed) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // 从种子生成确定性密钥对
        int result = crypto_sign_seed_keypair(public_key.data(), private_key.data(), seed.data());
        
        if (result != 0) {
            set_error("Failed to generate Ed25519 keypair from seed");
            return false;
        }
        
        increment_keypair_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        // 记录密钥生成时间（如果需要的话）
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 keypair from seed failed: " + std::string(e.what()));
        return false;
    }
}

bool Ed25519::derive_public_key(PublicKey& public_key, const PrivateKey& private_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // libsodium中，私钥实际上包含了公钥
        // 我们需要提取公钥部分
        
        // Ed25519私钥的后32字节是公钥
        std::memcpy(public_key.data(), private_key.data() + 32, 32);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        // 记录密钥生成时间（如果需要的话）
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 public key derivation failed: " + std::string(e.what()));
        return false;
    }
}

// ========== 签名/验证 ==========

bool Ed25519::sign(Signature& signature, const Message& message, const PrivateKey& private_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        unsigned long long sig_len;
        
        // 使用libsodium进行签名
        int result = crypto_sign_detached(
            signature.data(),
            &sig_len,
            message.data(),
            message.size(),
            private_key.data()
        );
        
        if (result != 0 || sig_len != signature.size()) {
            set_error("Ed25519 signing failed");
            return false;
        }
        
        increment_sign_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_sign_time(duration.count() / 1000.0);
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 signing failed: " + std::string(e.what()));
        return false;
    }
}

bool Ed25519::verify(const Signature& signature, const Message& message, const PublicKey& public_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        // 使用libsodium进行验证
        int result = crypto_sign_verify_detached(
            signature.data(),
            message.data(),
            message.size(),
            public_key.data()
        );
        
        bool success = (result == 0);
        
        increment_verify_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_verify_time(duration.count() / 1000.0);
        
        return success;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 verification failed: " + std::string(e.what()));
        return false;
    }
}

bool Ed25519::sign_detached(Signature& signature, const Message& message, const PrivateKey& private_key) {
    return sign(signature, message, private_key);
}

bool Ed25519::verify_detached(const Signature& signature, const Message& message, const PublicKey& public_key) {
    return verify(signature, message, public_key);
}

// ========== 多签名支持 ==========

bool Ed25519::aggregate_public_keys(PublicKey& aggregated_key, const std::vector<PublicKey>& public_keys) {
    if (public_keys.empty()) {
        set_error("No public keys to aggregate");
        return false;
    }
    
    try {
        // 简单的公钥聚合（XOR方式，不是真正的EdDSA聚合）
        // 注意：这不是标准的Ed25519聚合方式
        aggregated_key.fill(0);
        
        for (const auto& pk : public_keys) {
            for (size_t i = 0; i < aggregated_key.size(); ++i) {
                aggregated_key[i] ^= pk[i];
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 public key aggregation failed: " + std::string(e.what()));
        return false;
    }
}

bool Ed25519::verify_multisig(const std::vector<Signature>& signatures, 
                              const Message& message,
                              const std::vector<PublicKey>& public_keys,
                              size_t threshold) {
    if (signatures.size() != public_keys.size()) {
        set_error("Signature and public key count mismatch");
        return false;
    }
    
    if (signatures.size() < threshold) {
        set_error("Insufficient signatures for threshold");
        return false;
    }
    
    try {
        size_t valid_signatures = 0;
        
        // 验证每个签名
        for (size_t i = 0; i < signatures.size(); ++i) {
            if (verify(signatures[i], message, public_keys[i])) {
                valid_signatures++;
            }
        }
        
        return valid_signatures >= threshold;
        
    } catch (const std::exception& e) {
        set_error("Ed25519 multisig verification failed: " + std::string(e.what()));
        return false;
    }
}

// ========== 序列化/反序列化 ==========

std::string Ed25519::private_key_to_hex(const PrivateKey& key) {
    return to_hex(key);
}

std::string Ed25519::public_key_to_hex(const PublicKey& key) {
    return to_hex(key);
}

std::string Ed25519::signature_to_hex(const Signature& sig) {
    return to_hex(sig);
}

std::string Ed25519::seed_to_hex(const Seed& seed) {
    return to_hex(seed);
}

bool Ed25519::private_key_from_hex(PrivateKey& key, const std::string& hex) {
    return from_hex(key, hex);
}

bool Ed25519::public_key_from_hex(PublicKey& key, const std::string& hex) {
    return from_hex(key, hex);
}

bool Ed25519::signature_from_hex(Signature& sig, const std::string& hex) {
    return from_hex(sig, hex);
}

bool Ed25519::seed_from_hex(Seed& seed, const std::string& hex) {
    return from_hex(seed, hex);
}

std::string Ed25519::private_key_to_base64(const PrivateKey& key) {
    return to_base64(key.data(), key.size());
}

std::string Ed25519::public_key_to_base64(const PublicKey& key) {
    return to_base64(key.data(), key.size());
}

std::string Ed25519::signature_to_base64(const Signature& sig) {
    return to_base64(sig.data(), sig.size());
}

bool Ed25519::private_key_from_base64(PrivateKey& key, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != key.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), key.begin());
    return true;
}

bool Ed25519::public_key_from_base64(PublicKey& key, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != key.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), key.begin());
    return true;
}

bool Ed25519::signature_from_base64(Signature& sig, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != sig.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), sig.begin());
    return true;
}

// ========== 验证和工具 ==========

bool Ed25519::is_valid_private_key(const PrivateKey& private_key) {
    // 检查私钥不全为零
    for (auto byte : private_key) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

bool Ed25519::is_valid_public_key(const PublicKey& public_key) {
    // libsodium提供了公钥验证函数
    // 但我们做简单检查：不全为零
    for (auto byte : public_key) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

bool Ed25519::is_valid_signature(const Signature& signature) {
    // 检查签名不全为零
    for (auto byte : signature) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

bool Ed25519::generate_seed(Seed& seed) {
    return secure_random_bytes(seed);
}

} // namespace crypto
} // namespace duckchain 