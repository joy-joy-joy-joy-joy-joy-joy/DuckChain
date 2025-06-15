#include "crypto/core/secp256k1.hpp"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <memory>
#include <algorithm>

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

    // 工具函数: 创建secp256k1密钥对
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> createKeyPair() {
        // 创建secp256k1曲线
        std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
            EC_GROUP_new_by_curve_name(NID_secp256k1),
            EC_GROUP_free
        );
        if (!group) return {nullptr, EC_KEY_free};

        // 创建密钥对
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(
            EC_KEY_new(),
            EC_KEY_free
        );
        if (!key) return {nullptr, EC_KEY_free};

        // 设置曲线
        if (EC_KEY_set_group(key.get(), group.get()) != 1) {
            return {nullptr, EC_KEY_free};
        }

        // 生成密钥对
        if (EC_KEY_generate_key(key.get()) != 1) {
            return {nullptr, EC_KEY_free};
        }

        return key;
    }

    // 工具函数: 从EC_KEY导出私钥
    bool exportPrivateKey(EC_KEY* key, PrivateKey& out) {
        const BIGNUM* priv = EC_KEY_get0_private_key(key);
        if (!priv) return false;
        
        return BN_bn2binpad(priv, out.data(), out.size()) == static_cast<int>(out.size());
    }

    // 工具函数: 从EC_KEY导出公钥
    bool exportPublicKey(EC_KEY* key, PublicKey& out) {
        const EC_POINT* pub = EC_KEY_get0_public_key(key);
        if (!pub) return false;

        const EC_GROUP* group = EC_KEY_get0_group(key);
        if (!group) return false;

        size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED,
                                      out.data(), out.size(), nullptr);
        return len == out.size();
    }

    // 工具函数: 从私钥数据创建EC_KEY
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> createFromPrivateKey(const PrivateKey& privateKey) {
        // 创建secp256k1曲线
        std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
            EC_GROUP_new_by_curve_name(NID_secp256k1),
            EC_GROUP_free
        );
        if (!group) return {nullptr, EC_KEY_free};

        // 创建密钥对
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(
            EC_KEY_new(),
            EC_KEY_free
        );
        if (!key) return {nullptr, EC_KEY_free};

        // 设置曲线
        if (EC_KEY_set_group(key.get(), group.get()) != 1) {
            return {nullptr, EC_KEY_free};
        }

        // 设置私钥
        BIGNUM* priv = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
        if (!priv) return {nullptr, EC_KEY_free};

        if (EC_KEY_set_private_key(key.get(), priv) != 1) {
            BN_free(priv);
            return {nullptr, EC_KEY_free};
        }

        // 计算公钥
        EC_POINT* pub = EC_POINT_new(group.get());
        if (!pub) {
            BN_free(priv);
            return {nullptr, EC_KEY_free};
        }

        if (EC_POINT_mul(group.get(), pub, priv, nullptr, nullptr, nullptr) != 1) {
            EC_POINT_free(pub);
            BN_free(priv);
            return {nullptr, EC_KEY_free};
        }

        if (EC_KEY_set_public_key(key.get(), pub) != 1) {
            EC_POINT_free(pub);
            BN_free(priv);
            return {nullptr, EC_KEY_free};
        }

        EC_POINT_free(pub);
        BN_free(priv);

        return key;
    }

    // 工具函数: 从公钥数据创建EC_KEY
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> createFromPublicKey(const PublicKey& publicKey) {
        // 创建secp256k1曲线
        std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
            EC_GROUP_new_by_curve_name(NID_secp256k1),
            EC_GROUP_free
        );
        if (!group) return {nullptr, EC_KEY_free};

        // 创建密钥对
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key(
            EC_KEY_new(),
            EC_KEY_free
        );
        if (!key) return {nullptr, EC_KEY_free};

        // 设置曲线
        if (EC_KEY_set_group(key.get(), group.get()) != 1) {
            return {nullptr, EC_KEY_free};
        }

        // 从压缩格式解析公钥点
        EC_POINT* pub = EC_POINT_new(group.get());
        if (!pub) return {nullptr, EC_KEY_free};

        if (EC_POINT_oct2point(group.get(), pub, publicKey.data(), publicKey.size(), nullptr) != 1) {
            EC_POINT_free(pub);
            return {nullptr, EC_KEY_free};
        }

        if (EC_KEY_set_public_key(key.get(), pub) != 1) {
            EC_POINT_free(pub);
            return {nullptr, EC_KEY_free};
        }

        EC_POINT_free(pub);

        return key;
    }
}

Secp256k1::Secp256k1() {}

Secp256k1::~Secp256k1() {}

std::optional<std::pair<PrivateKey, PublicKey>> Secp256k1::generateKeyPair() noexcept {
    try {
        auto key = createKeyPair();
        if (!key) {
            setError("Failed to create key pair: " + getOpenSSLError());
            return std::nullopt;
        }

        PrivateKey private_key = {};
        if (!exportPrivateKey(key.get(), private_key)) {
            setError("Failed to export private key: " + getOpenSSLError());
            return std::nullopt;
        }

        PublicKey public_key = {};
        if (!exportPublicKey(key.get(), public_key)) {
            setError("Failed to export public key: " + getOpenSSLError());
            return std::nullopt;
        }

        return std::make_pair(private_key, public_key);
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

std::optional<PublicKey> Secp256k1::derivePublicKey(const PrivateKey& privateKey) noexcept {
    try {
        auto key = createFromPrivateKey(privateKey);
        if (!key) {
            setError("Failed to create key from private key: " + getOpenSSLError());
            return std::nullopt;
        }

        PublicKey public_key = {};
        if (!exportPublicKey(key.get(), public_key)) {
            setError("Failed to export public key: " + getOpenSSLError());
            return std::nullopt;
        }

        return public_key;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

std::optional<Signature> Secp256k1::sign(const Bytes& message, const PrivateKey& privateKey) noexcept {
    try {
        auto key = createFromPrivateKey(privateKey);
        if (!key) {
            setError("Failed to create key from private key: " + getOpenSSLError());
            return std::nullopt;
        }

        // 计算消息哈希
        auto hash = sha256(message);

        // 签名
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
            ECDSA_do_sign(hash.data(), hash.size(), key.get()),
            ECDSA_SIG_free
        );
        if (!sig) {
            setError("Failed to create signature: " + getOpenSSLError());
            return std::nullopt;
        }

        // 获取r和s值
        const BIGNUM* r = ECDSA_SIG_get0_r(sig.get());
        const BIGNUM* s = ECDSA_SIG_get0_s(sig.get());
        if (!r || !s) {
            setError("Failed to get r and s values: " + getOpenSSLError());
            return std::nullopt;
        }

        // 转换为R,S格式
        Signature signature = {};
        if (BN_bn2binpad(r, signature.data(), 32) != 32 ||
            BN_bn2binpad(s, signature.data() + 32, 32) != 32) {
            setError("Failed to convert signature to R,S format: " + getOpenSSLError());
            return std::nullopt;
        }

        return signature;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

bool Secp256k1::verify(const Bytes& message, const Signature& signature, const PublicKey& publicKey) noexcept {
    try {
        auto key = createFromPublicKey(publicKey);
        if (!key) {
            setError("Failed to create key from public key: " + getOpenSSLError());
            return false;
        }

        // 计算消息哈希
        auto hash = sha256(message);

        // 从R,S格式创建ECDSA_SIG
        std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)> sig(
            ECDSA_SIG_new(),
            ECDSA_SIG_free
        );
        if (!sig) {
            setError("Failed to create ECDSA_SIG: " + getOpenSSLError());
            return false;
        }

        // 设置r和s值
        BIGNUM* r = BN_bin2bn(signature.data(), 32, nullptr);
        BIGNUM* s = BN_bin2bn(signature.data() + 32, 32, nullptr);
        if (!r || !s) {
            BN_free(r);
            BN_free(s);
            setError("Failed to convert R,S to BIGNUM: " + getOpenSSLError());
            return false;
        }

        if (ECDSA_SIG_set0(sig.get(), r, s) != 1) {
            BN_free(r);
            BN_free(s);
            setError("Failed to set r and s values: " + getOpenSSLError());
            return false;
        }

        // 验证签名
        int result = ECDSA_do_verify(hash.data(), hash.size(), sig.get(), key.get());
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

std::optional<std::array<uint8_t, 20>> Secp256k1::deriveAddress(const PublicKey& publicKey) noexcept {
    try {
        // 检查公钥格式
        if (publicKey[0] != 0x02 && publicKey[0] != 0x03) {
            setError("Invalid public key format");
            return std::nullopt;
        }

        // 计算Keccak-256哈希
        auto hash = keccak256(std::vector<uint8_t>(publicKey.begin() + 1, publicKey.end()));
        
        // 取最后20字节作为地址
        std::array<uint8_t, 20> address;
        std::copy(hash.end() - 20, hash.end(), address.begin());
        
        return address;
    } catch (const std::exception& e) {
        setError(std::string("Unexpected error: ") + e.what());
        return std::nullopt;
    }
}

} // namespace crypto
} // namespace duckchain 