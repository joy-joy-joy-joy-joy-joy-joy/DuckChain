#include "crypto/core/secp256k1.hpp"
#include <secp256k1.h>
#include <chrono>
#include <cstring>

namespace duckchain {
namespace crypto {

using namespace utils;

// ========== 构造/析构 ==========

Secp256k1::Secp256k1() : context_(nullptr) {
    // 创建secp256k1上下文
    context_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!context_) {
        set_error("Failed to create secp256k1 context");
    }
}

Secp256k1::~Secp256k1() {
    if (context_) {
        secp256k1_context_destroy(static_cast<secp256k1_context*>(context_));
    }
    }

// ========== 密钥生成 ==========

bool Secp256k1::generate_private_key(PrivateKey& private_key) {
    if (!context_) {
        set_error("secp256k1 context not initialized");
        return false;
    }
    
    try {
        // 生成随机私钥，并验证有效性
        do {
            if (!secure_random_bytes(private_key)) {
                set_error("Failed to generate random bytes for private key");
                return false;
            }
        } while (!secp256k1_ec_seckey_verify(static_cast<secp256k1_context*>(context_), private_key.data()));
        
        increment_key_count();
        return true;
        
    } catch (const std::exception& e) {
        set_error("secp256k1 private key generation failed: " + std::string(e.what()));
        return false;
        }
}

bool Secp256k1::derive_public_key(PublicKey& public_key, const PrivateKey& private_key) {
    if (!context_) {
        set_error("secp256k1 context not initialized");
        return false;
        }

    try {
        secp256k1_pubkey pubkey;
        
        // 从私钥创建公钥
        if (!secp256k1_ec_pubkey_create(static_cast<secp256k1_context*>(context_), &pubkey, private_key.data())) {
            set_error("Failed to create public key from private key");
            return false;
        }

        // 序列化公钥（压缩格式）
        size_t output_len = public_key.size();
        if (!secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(context_), 
                                          public_key.data(), &output_len, &pubkey, 
                                          SECP256K1_EC_COMPRESSED)) {
            set_error("Failed to serialize public key");
            return false;
        }

        if (output_len != public_key.size()) {
            set_error("Public key serialization length mismatch");
            return false;
        }

        return true;
        
    } catch (const std::exception& e) {
        set_error("secp256k1 public key derivation failed: " + std::string(e.what()));
        return false;
    }
}

// ========== ECDSA签名/验证 ==========

bool Secp256k1::sign_ecdsa(Signature& signature, const Hash& message_hash, const PrivateKey& private_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (!context_) {
        set_error("secp256k1 context not initialized");
        return false;
        }

    try {
        secp256k1_ecdsa_signature sig;
        
        // 创建ECDSA签名
        if (!secp256k1_ecdsa_sign(static_cast<secp256k1_context*>(context_), &sig, 
                                 message_hash.data(), private_key.data(), nullptr, nullptr)) {
            set_error("Failed to create ECDSA signature");
            return false;
        }

        // 序列化签名为紧凑格式
        if (!secp256k1_ecdsa_signature_serialize_compact(static_cast<secp256k1_context*>(context_),
                                                        signature.data(), &sig)) {
            set_error("Failed to serialize ECDSA signature");
            return false;
        }

        increment_sign_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_sign_time(duration.count() / 1000.0);
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("secp256k1 ECDSA signing failed: " + std::string(e.what()));
        return false;
    }
}

bool Secp256k1::verify_ecdsa(const Signature& signature, const Hash& message_hash, const PublicKey& public_key) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    if (!context_) {
        set_error("secp256k1 context not initialized");
            return false;
        }

    try {
        secp256k1_ecdsa_signature sig;
        secp256k1_pubkey pubkey;

        // 解析紧凑格式签名
        if (!secp256k1_ecdsa_signature_parse_compact(static_cast<secp256k1_context*>(context_),
                                                    &sig, signature.data())) {
            set_error("Failed to parse ECDSA signature");
            return false;
        }

        // 解析公钥
        if (!secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(context_),
                                      &pubkey, public_key.data(), public_key.size())) {
            set_error("Failed to parse public key");
            return false;
        }

        // 验证签名
        bool result = secp256k1_ecdsa_verify(static_cast<secp256k1_context*>(context_),
                                           &sig, message_hash.data(), &pubkey) == 1;
        
        increment_verify_count();
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        record_verify_time(duration.count() / 1000.0);
        
        return result;
        
    } catch (const std::exception& e) {
        set_error("secp256k1 ECDSA verification failed: " + std::string(e.what()));
        return false;
    }
}

// ========== 序列化/反序列化 ==========

std::string Secp256k1::private_key_to_hex(const PrivateKey& key) {
    return to_hex(key);
}

std::string Secp256k1::public_key_to_hex(const PublicKey& key) {
    return to_hex(key);
}

std::string Secp256k1::signature_to_hex(const Signature& sig) {
    return to_hex(sig);
}

bool Secp256k1::private_key_from_hex(PrivateKey& key, const std::string& hex) {
    return from_hex(key, hex);
}

bool Secp256k1::public_key_from_hex(PublicKey& key, const std::string& hex) {
    return from_hex(key, hex);
        }

bool Secp256k1::signature_from_hex(Signature& sig, const std::string& hex) {
    return from_hex(sig, hex);
}

// ========== 验证和工具 ==========

bool Secp256k1::is_valid_private_key(const PrivateKey& private_key) {
    if (!context_) {
        return false;
    }
    return secp256k1_ec_seckey_verify(static_cast<secp256k1_context*>(context_), private_key.data()) == 1;
}

bool Secp256k1::is_valid_public_key(const PublicKey& public_key) {
    if (!context_) {
        return false;
    }
    secp256k1_pubkey pubkey;
    return secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(context_),
                                    &pubkey, public_key.data(), public_key.size()) == 1;
}

Secp256k1::Hash Secp256k1::hash_message(const Message& message) {
    return sha256(message);
}

// ========== 私有方法 ==========

void Secp256k1::record_sign_time(double time_ms) const {
    stats_.total_sign_time_ms += time_ms;
}

void Secp256k1::record_verify_time(double time_ms) const {
    stats_.total_verify_time_ms += time_ms;
}

} // namespace crypto
} // namespace duckchain 