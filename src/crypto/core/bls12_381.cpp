#include "crypto/core/bls12_381.hpp"
#include <blst.h>
#include <chrono>
#include <cstring>

namespace duckchain {
namespace crypto {

using namespace utils;

// DST (Domain Separation Tag) for BLS signatures
static const char BLS_SIG_DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
static const size_t BLS_SIG_DST_LEN = sizeof(BLS_SIG_DST) - 1;

// ========== 密钥生成 ==========

bool BLS12_381::generate_private_key(PrivateKey& private_key) {
    try {
        // 生成符合BLS12-381标准的私钥
        do {
            if (!secure_random_bytes(private_key)) {
                set_error("Failed to generate random bytes for BLS private key");
                return false;
            }
        } while (!is_valid_private_key(private_key));
        
        increment_key_count();
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 private key generation failed: " + std::string(e.what()));
        return false;
    }
}

bool BLS12_381::derive_public_key(PublicKey& public_key, const PrivateKey& private_key) {
    try {
        blst_scalar sk;
        blst_p1 pk;
        
        // 将私钥转换为scalar
        blst_scalar_from_bendian(&sk, private_key.data());
        
        // 检查私钥有效性
        if (blst_scalar_fr_check(&sk) == 0) {
            set_error("Invalid BLS private key");
            return false;
        }
        
        // 生成公钥：G1点 * 私钥
        blst_sk_to_pk_in_g1(&pk, &sk);
        
        // 序列化公钥为压缩格式
        blst_p1_compress(public_key.data(), &pk);
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 public key derivation failed: " + std::string(e.what()));
        return false;
    }
}

bool BLS12_381::keypair_from_seed(PrivateKey& private_key, PublicKey& public_key, const std::vector<uint8_t>& seed) {
    try {
        if (seed.size() < 32) {
            set_error("BLS seed must be at least 32 bytes");
            return false;
        }
        
        // 使用HKDF-SHA256从种子派生私钥
        blst_scalar sk;
        blst_keygen(&sk, seed.data(), seed.size(), nullptr, 0);
        
        // 将scalar转换为字节数组
        blst_bendian_from_scalar(private_key.data(), &sk);
        
        // 生成对应的公钥
        if (!derive_public_key(public_key, private_key)) {
            return false;
        }
        
        increment_key_count();
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 keypair from seed failed: " + std::string(e.what()));
        return false;
    }
}

// ========== 基础签名/验证 ==========

bool BLS12_381::sign(Signature& signature, const Message& message, const PrivateKey& private_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        blst_scalar sk;
        blst_p2 sig;
        
        // 转换私钥
        blst_scalar_from_bendian(&sk, private_key.data());
        
        if (blst_scalar_fr_check(&sk) == 0) {
            set_error("Invalid BLS private key for signing");
            return false;
        }
        
        // 对消息进行哈希到G2
        blst_p2 msg_point;
        blst_hash_to_g2(&msg_point, message.data(), message.size(), 
                        reinterpret_cast<const uint8_t*>(BLS_SIG_DST), BLS_SIG_DST_LEN, 
                        nullptr, 0);
        
        // 创建签名：msg_hash * 私钥
        sig = msg_point;
        blst_p2_mult(&sig, &sig, sk.b, 256);
        
        // 序列化签名
        blst_p2_compress(signature.data(), &sig);
        
        increment_sign_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_sign_time(duration.count() / 1000.0);
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 signing failed: " + std::string(e.what()));
        return false;
    }
}

bool BLS12_381::verify(const Signature& signature, const Message& message, const PublicKey& public_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        blst_p1_affine pk;
        blst_p2_affine sig;
        
        // 解压缩公钥
        if (blst_p1_uncompress(&pk, public_key.data()) != BLST_SUCCESS) {
            set_error("Failed to decompress BLS public key");
            return false;
        }
        
        // 检查公钥有效性
        if (!blst_p1_affine_in_g1(&pk)) {
            set_error("Invalid BLS public key");
            return false;
        }
        
        // 解压缩签名
        if (blst_p2_uncompress(&sig, signature.data()) != BLST_SUCCESS) {
            set_error("Failed to decompress BLS signature");
            return false;
        }
        
        // 检查签名有效性
        if (!blst_p2_affine_in_g2(&sig)) {
            set_error("Invalid BLS signature");
            return false;
        }
        
        // 验证签名：使用blst的core verify函数
        BLST_ERROR result = blst_core_verify_pk_in_g1(&pk, &sig, 1, 
                                                     message.data(), message.size(),
                                                     reinterpret_cast<const uint8_t*>(BLS_SIG_DST), BLS_SIG_DST_LEN,
                                                     nullptr, 0);
        
        bool success = (result == BLST_SUCCESS);
        
        increment_verify_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_verify_time(duration.count() / 1000.0);
        
        return success;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 verification failed: " + std::string(e.what()));
        return false;
    }
}

// ========== 聚合签名 ==========

bool BLS12_381::aggregate_signatures(Signature& aggregated_signature, const std::vector<Signature>& signatures) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (signatures.empty()) {
        set_error("No signatures to aggregate");
        return false;
    }
    
    try {
        blst_p2 agg_sig;
        bool first = true;
        
        for (const auto& sig_bytes : signatures) {
            blst_p2_affine sig;
            
            // 解压缩签名
            if (blst_p2_uncompress(&sig, sig_bytes.data()) != BLST_SUCCESS) {
                set_error("Failed to decompress signature for aggregation");
                return false;
            }
            
            if (!blst_p2_affine_in_g2(&sig)) {
                set_error("Invalid signature for aggregation");
                return false;
            }
            
            if (first) {
                blst_p2_from_affine(&agg_sig, &sig);
                first = false;
            } else {
                blst_p2 temp;
                blst_p2_from_affine(&temp, &sig);
                blst_p2_add(&agg_sig, &agg_sig, &temp);
            }
        }
        
        // 序列化聚合签名
        blst_p2_compress(aggregated_signature.data(), &agg_sig);
        
        increment_aggregate_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_aggregate_time(duration.count() / 1000.0);
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 signature aggregation failed: " + std::string(e.what()));
        return false;
    }
}

bool BLS12_381::aggregate_public_keys(PublicKey& aggregated_key, const std::vector<PublicKey>& public_keys) {
    if (public_keys.empty()) {
        set_error("No public keys to aggregate");
        return false;
    }
    
    try {
        blst_p1 agg_pk;
        bool first = true;
        
        for (const auto& pk_bytes : public_keys) {
            blst_p1_affine pk;
            
            // 解压缩公钥
            if (blst_p1_uncompress(&pk, pk_bytes.data()) != BLST_SUCCESS) {
                set_error("Failed to decompress public key for aggregation");
                return false;
            }
            
            if (!blst_p1_affine_in_g1(&pk)) {
                set_error("Invalid public key for aggregation");
                return false;
            }
            
            if (first) {
                blst_p1_from_affine(&agg_pk, &pk);
                first = false;
            } else {
                blst_p1 temp;
                blst_p1_from_affine(&temp, &pk);
                blst_p1_add(&agg_pk, &agg_pk, &temp);
            }
        }
        
        // 序列化聚合公钥
        blst_p1_compress(aggregated_key.data(), &agg_pk);
        
        increment_pubkey_aggregate_count();
        return true;
        
    } catch (const std::exception& e) {
        set_error("BLS12-381 public key aggregation failed: " + std::string(e.what()));
        return false;
    }
}

bool BLS12_381::verify_aggregated_same_message(const Signature& aggregated_signature,
                                              const Message& message,
                                              const std::vector<PublicKey>& public_keys) {
    // 聚合公钥
    PublicKey aggregated_pk;
    if (!aggregate_public_keys(aggregated_pk, public_keys)) {
        return false;
    }
    
    // 使用聚合公钥验证聚合签名
    return verify(aggregated_signature, message, aggregated_pk);
}

// ========== 序列化/反序列化 ==========

std::string BLS12_381::private_key_to_hex(const PrivateKey& key) {
    return to_hex(key);
}

std::string BLS12_381::public_key_to_hex(const PublicKey& key) {
    return to_hex(key);
}

std::string BLS12_381::signature_to_hex(const Signature& sig) {
    return to_hex(sig);
}

bool BLS12_381::private_key_from_hex(PrivateKey& key, const std::string& hex) {
    return from_hex(key, hex);
}

bool BLS12_381::public_key_from_hex(PublicKey& key, const std::string& hex) {
    return from_hex(key, hex);
}

bool BLS12_381::signature_from_hex(Signature& sig, const std::string& hex) {
    return from_hex(sig, hex);
}

std::string BLS12_381::private_key_to_base64(const PrivateKey& key) {
    return to_base64(key.data(), key.size());
}

std::string BLS12_381::public_key_to_base64(const PublicKey& key) {
    return to_base64(key.data(), key.size());
}

std::string BLS12_381::signature_to_base64(const Signature& sig) {
    return to_base64(sig.data(), sig.size());
}

bool BLS12_381::private_key_from_base64(PrivateKey& key, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != key.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), key.begin());
    return true;
}

bool BLS12_381::public_key_from_base64(PublicKey& key, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != key.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), key.begin());
    return true;
}

bool BLS12_381::signature_from_base64(Signature& sig, const std::string& base64) {
    std::vector<uint8_t> temp;
    if (!from_base64(temp, base64) || temp.size() != sig.size()) {
        return false;
    }
    std::copy(temp.begin(), temp.end(), sig.begin());
    return true;
}

// ========== 验证和工具 ==========

bool BLS12_381::is_valid_private_key(const PrivateKey& private_key) {
    blst_scalar sk;
    blst_scalar_from_bendian(&sk, private_key.data());
    return blst_scalar_fr_check(&sk) != 0;
}

bool BLS12_381::is_valid_public_key(const PublicKey& public_key) {
    blst_p1_affine pk;
    if (blst_p1_uncompress(&pk, public_key.data()) != BLST_SUCCESS) {
        return false;
    }
    return blst_p1_affine_in_g1(&pk);
}

bool BLS12_381::is_valid_signature(const Signature& signature) {
    blst_p2_affine sig;
    if (blst_p2_uncompress(&sig, signature.data()) != BLST_SUCCESS) {
        return false;
    }
    return blst_p2_affine_in_g2(&sig);
}

// ========== 私有方法 ==========

void BLS12_381::record_sign_time(double time_ms) const {
    stats_.total_sign_time_ms += time_ms;
}

void BLS12_381::record_verify_time(double time_ms) const {
    stats_.total_verify_time_ms += time_ms;
}

void BLS12_381::record_aggregate_time(double time_ms) const {
    stats_.total_aggregate_time_ms += time_ms;
}

} // namespace crypto
} // namespace duckchain 