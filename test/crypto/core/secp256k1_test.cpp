#include <gtest/gtest.h>
#include "crypto/core/secp256k1.hpp"

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

// ========== 密钥生成测试 ==========

TEST_F(Secp256k1Test, GeneratePrivateKey) {
    Secp256k1::PrivateKey private_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->is_valid_private_key(private_key));
}

TEST_F(Secp256k1Test, DerivePublicKey) {
    Secp256k1::PrivateKey private_key;
    Secp256k1::PublicKey public_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->derive_public_key(public_key, private_key));
    EXPECT_TRUE(secp256k1->is_valid_public_key(public_key));
}

// ========== ECDSA签名和验证测试 ==========

TEST_F(Secp256k1Test, ECDSASignAndVerify) {
    Secp256k1::PrivateKey private_key;
    Secp256k1::PublicKey public_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->derive_public_key(public_key, private_key));
    
    std::string message_str = "Hello, secp256k1!";
    Secp256k1::Message message(message_str.begin(), message_str.end());
    auto message_hash = secp256k1->hash_message(message);
    Secp256k1::Signature signature;
    
    // 签名
    EXPECT_TRUE(secp256k1->sign_ecdsa(signature, message_hash, private_key));
    
    // 验证
    EXPECT_TRUE(secp256k1->verify_ecdsa(signature, message_hash, public_key));
}

TEST_F(Secp256k1Test, ECDSAVerifyWithWrongHash) {
    Secp256k1::PrivateKey private_key;
    Secp256k1::PublicKey public_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->derive_public_key(public_key, private_key));
    
    std::string message_str = "Original message";
    Secp256k1::Message message(message_str.begin(), message_str.end());
    auto message_hash = secp256k1->hash_message(message);
    Secp256k1::Signature signature;
    
    EXPECT_TRUE(secp256k1->sign_ecdsa(signature, message_hash, private_key));
    
    // 用错误的消息哈希验证应该失败
    std::string wrong_message_str = "Wrong message";
    Secp256k1::Message wrong_message(wrong_message_str.begin(), wrong_message_str.end());
    auto wrong_hash = secp256k1->hash_message(wrong_message);
    EXPECT_FALSE(secp256k1->verify_ecdsa(signature, wrong_hash, public_key));
}

// ========== 序列化测试 ==========

TEST_F(Secp256k1Test, HexSerialization) {
    Secp256k1::PrivateKey private_key;
    Secp256k1::PublicKey public_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->derive_public_key(public_key, private_key));
    
    // 私钥序列化
    std::string private_hex = secp256k1->private_key_to_hex(private_key);
    EXPECT_EQ(private_hex.length(), 64);  // 32字节 = 64个十六进制字符
    
    Secp256k1::PrivateKey private_key_restored;
    EXPECT_TRUE(secp256k1->private_key_from_hex(private_key_restored, private_hex));
    EXPECT_EQ(private_key, private_key_restored);
}

// ========== 性能测试 ==========

TEST_F(Secp256k1Test, SigningPerformance) {
    Secp256k1::PrivateKey private_key;
    Secp256k1::PublicKey public_key;
    
    EXPECT_TRUE(secp256k1->generate_private_key(private_key));
    EXPECT_TRUE(secp256k1->derive_public_key(public_key, private_key));
    
    std::string message_str = "Performance test";
    Secp256k1::Message message(message_str.begin(), message_str.end());
    auto message_hash = secp256k1->hash_message(message);
    
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        Secp256k1::Signature signature;
        EXPECT_TRUE(secp256k1->sign_ecdsa(signature, message_hash, private_key));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / iterations;
    std::cout << "Average secp256k1 ECDSA signing time: " << avg_time << " μs" << std::endl;
    
    EXPECT_LT(avg_time, 1000);  // 少于1ms
} 