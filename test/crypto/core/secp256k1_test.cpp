#include <gtest/gtest.h>
#include "crypto/core/secp256k1.hpp"
#include <array>

using namespace duckchain::crypto;

class Secp256k1Test : public ::testing::Test {
protected:
    void SetUp() override {
        secp256k1 = std::make_unique<Secp256k1>();
    }

    void TearDown() override {
        secp256k1.reset();
    }

    std::unique_ptr<Secp256k1> secp256k1;
};

// 基本功能测试
TEST_F(Secp256k1Test, KeyGeneration) {
    auto key_pair = secp256k1->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value()) << secp256k1->getLastError();
    
    const auto& [priv_key, pub_key] = *key_pair;
    EXPECT_EQ(priv_key.size(), 32);
    EXPECT_EQ(pub_key.size(), 33);
    EXPECT_TRUE(pub_key[0] == 0x02 || pub_key[0] == 0x03) << "Invalid public key format";
}

TEST_F(Secp256k1Test, PublicKeyDerivation) {
    auto key_pair = secp256k1->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    auto derived_pub = secp256k1->derivePublicKey(priv_key);
    
    ASSERT_TRUE(derived_pub.has_value()) << secp256k1->getLastError();
    EXPECT_EQ(*derived_pub, pub_key);
}

// 签名测试
TEST_F(Secp256k1Test, SignAndVerify) {
    auto key_pair = secp256k1->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes message = {1, 2, 3, 4, 5};
    
    auto signature = secp256k1->sign(message, priv_key);
    ASSERT_TRUE(signature.has_value()) << secp256k1->getLastError();
    
    bool verified = secp256k1->verify(message, *signature, pub_key);
    EXPECT_TRUE(verified) << secp256k1->getLastError();
}

// 地址生成测试
TEST_F(Secp256k1Test, AddressGeneration) {
    auto key_pair = secp256k1->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    auto address = secp256k1->deriveAddress(pub_key);
    
    ASSERT_TRUE(address.has_value()) << secp256k1->getLastError();
    EXPECT_EQ(address->size(), 20);
}

// 错误处理测试
TEST_F(Secp256k1Test, InvalidPrivateKey) {
    PrivateKey invalid_key = {};  // 全0私钥
    auto pub_key = secp256k1->derivePublicKey(invalid_key);
    EXPECT_FALSE(pub_key.has_value()) << "Should fail with invalid private key";
    EXPECT_FALSE(secp256k1->getLastError().empty()) << "Should have error message";
}

// 性能测试
TEST_F(Secp256k1Test, SigningPerformance) {
    auto key_pair = secp256k1->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes message(32, 0x42);  // 32字节消息
    
    auto start = std::chrono::high_resolution_clock::now();
    for(int i = 0; i < 100; i++) {
        auto signature = secp256k1->sign(message, priv_key);
        ASSERT_TRUE(signature.has_value());
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "100 signatures took " << duration.count() << "ms" << std::endl;
} 