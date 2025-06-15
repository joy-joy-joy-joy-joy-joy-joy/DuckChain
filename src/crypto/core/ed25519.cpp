#include "crypto/core/ed25519.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>

namespace duckchain {
namespace crypto {

namespace {
    // 工具函数: 获取OpenSSL错误信息
    std::string getOpenSSLError() {
        char err_buf[256];
        unsigned long err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    // 工具函数: 计算SHA256哈希
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(32);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx.get(), data.data(), data.size());
        EVP_DigestFinal_ex(ctx.get(), hash.data(), nullptr);
        return hash;
    }

    // 工具函数: 计算Keccak-256哈希
    std::vector<uint8_t> keccak256(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> hash(32);
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );
        EVP_DigestInit_ex(ctx.get(), EVP_sha3_256(), nullptr);
        EVP_DigestUpdate(ctx.get(), data.data(), data.size());
        EVP_DigestFinal_ex(ctx.get(), hash.data(), nullptr);
        return hash;
    }
}

Ed25519::Ed25519() {}

Ed25519::~Ed25519() {}

std::optional<std::pair<Ed25519PrivateKey, Ed25519PublicKey>> Ed25519::generateKeyPair() noexcept {
    try {
        // 创建密钥对
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
            EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
            EVP_PKEY_CTX_free
        );
        if (!ctx) {
            setError("Failed to create key context: " + getOpenSSLError());
            return std::nullopt;
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            setError("Failed to initialize key generation: " + getOpenSSLError());
            return std::nullopt;
        }

        EVP_PKEY* pkey_raw = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
            setError("Failed to generate key pair: " + getOpenSSLError());
            return std::nullopt;
        }
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_raw, EVP_PKEY_free);

        // 导出私钥
        Ed25519PrivateKey private_key;
        size_t private_key_len = private_key.size();
        if (EVP_PKEY_get_raw_private_key(pkey.get(), private_key.data(), &private_key_len) <= 0) {
            setError("Failed to export private key: " + getOpenSSLError());
            return std::nullopt;
        }

        // 导出公钥
        Ed25519PublicKey public_key;
        size_t public_key_len = public_key.size();
        if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &public_key_len) <= 0) {
            setError("Failed to export public key: " + getOpenSSLError());
            return std::nullopt;
        }

        return std::make_pair(private_key, public_key);
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

std::optional<Ed25519PublicKey> Ed25519::derivePublicKey(const Ed25519PrivateKey& privateKey) noexcept {
    try {
        // 检查私钥是否全为0
        bool all_zero = true;
        for (auto byte : privateKey) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            setError("Invalid private key: all zeros");
            return std::nullopt;
        }

        // 从私钥创建 EVP_PKEY
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privateKey.data(), privateKey.size()),
            EVP_PKEY_free
        );
        if (!pkey) {
            setError("Failed to create key from private key: " + getOpenSSLError());
            return std::nullopt;
        }

        // 导出公钥
        Ed25519PublicKey public_key;
        size_t public_key_len = public_key.size();
        if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &public_key_len) <= 0) {
            setError("Failed to export public key: " + getOpenSSLError());
            return std::nullopt;
        }

        return public_key;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

std::optional<Ed25519Signature> Ed25519::sign(const Bytes& message, const Ed25519PrivateKey& privateKey) noexcept {
    try {
        // 检查私钥是否全为0
        bool all_zero = true;
        for (auto byte : privateKey) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            setError("Invalid private key: all zeros");
            return std::nullopt;
        }

        // 从私钥创建 EVP_PKEY
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privateKey.data(), privateKey.size()),
            EVP_PKEY_free
        );
        if (!pkey) {
            setError("Failed to create key from private key: " + getOpenSSLError());
            return std::nullopt;
        }

        // 创建签名上下文
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );
        if (!ctx) {
            setError("Failed to create signature context: " + getOpenSSLError());
            return std::nullopt;
        }

        // 初始化签名
        if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
            setError("Failed to initialize signature: " + getOpenSSLError());
            return std::nullopt;
        }

        // 签名
        Ed25519Signature signature;
        size_t sig_len = signature.size();
        if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, message.data(), message.size()) <= 0) {
            setError("Failed to create signature: " + getOpenSSLError());
            return std::nullopt;
        }

        return signature;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

bool Ed25519::verify(const Bytes& message, const Ed25519Signature& signature, const Ed25519PublicKey& publicKey) noexcept {
    try {
        // 检查公钥是否全为0
        bool all_zero = true;
        for (auto byte : publicKey) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            setError("Invalid public key: all zeros");
            return false;
        }

        // 从公钥创建 EVP_PKEY
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
            EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.data(), publicKey.size()),
            EVP_PKEY_free
        );
        if (!pkey) {
            setError("Failed to create key from public key: " + getOpenSSLError());
            return false;
        }

        // 创建验证上下文
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
            EVP_MD_CTX_new(),
            EVP_MD_CTX_free
        );
        if (!ctx) {
            setError("Failed to create verification context: " + getOpenSSLError());
            return false;
        }

        // 初始化验证
        if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
            setError("Failed to initialize verification: " + getOpenSSLError());
            return false;
        }

        // 验证签名
        int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                    message.data(), message.size());
        if (result < 0) {
            setError("Signature verification failed: " + getOpenSSLError());
            return false;
        }

        return result == 1;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return false;
    }
}

std::optional<Ed25519Address> Ed25519::deriveAddress(const Ed25519PublicKey& publicKey) noexcept {
    try {
        // 检查公钥是否全为0
        bool all_zero = true;
        for (auto byte : publicKey) {
            if (byte != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            setError("Invalid public key: all zeros");
            return std::nullopt;
        }

        // 计算公钥的 SHA3-256 哈希
        auto hash = keccak256(std::vector<uint8_t>(publicKey.begin(), publicKey.end()));
        
        // 取最后20字节作为地址
        Ed25519Address address;
        std::copy(hash.end() - address.size(), hash.end(), address.begin());
        
        return address;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

} // namespace crypto
} // namespace duckchain 