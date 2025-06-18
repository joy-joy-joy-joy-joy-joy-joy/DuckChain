#include <gtest/gtest.h>
#include "crypto/core/bls12_381.hpp"

using namespace duckchain::crypto;

class BLS12_381Test : public ::testing::Test {
protected:
    void SetUp() override {
        bls = std::make_unique<BLS12_381>();
    }
    
    void TearDown() override {
        bls.reset();
    }
    
    std::unique_ptr<BLS12_381> bls;
};

// ========== 密钥生成测试 ==========

TEST_F(BLS12_381Test, GeneratePrivateKey) {
    BLS12_381::PrivateKey private_key;
    
    EXPECT_TRUE(bls->generate_private_key(private_key));
    EXPECT_TRUE(bls->is_valid_private_key(private_key));
}

TEST_F(BLS12_381Test, DerivePublicKey) {
    BLS12_381::PrivateKey private_key;
    BLS12_381::PublicKey public_key;
    
    EXPECT_TRUE(bls->generate_private_key(private_key));
    EXPECT_TRUE(bls->derive_public_key(public_key, private_key));
    EXPECT_TRUE(bls->is_valid_public_key(public_key));
}

// ========== 基础签名和验证测试 ==========

TEST_F(BLS12_381Test, SignAndVerify) {
    BLS12_381::PrivateKey private_key;
    BLS12_381::PublicKey public_key;
    
    EXPECT_TRUE(bls->generate_private_key(private_key));
    EXPECT_TRUE(bls->derive_public_key(public_key, private_key));
    
    std::string message_str = "Hello, BLS12-381!";
    BLS12_381::Message message(message_str.begin(), message_str.end());
    BLS12_381::Signature signature;
    
    // 签名
    EXPECT_TRUE(bls->sign(signature, message, private_key));
    EXPECT_TRUE(bls->is_valid_signature(signature));
    
    // 验证
    EXPECT_TRUE(bls->verify(signature, message, public_key));
}

// ========== 聚合签名测试 ==========

TEST_F(BLS12_381Test, AggregateSignatures) {
    const size_t num_keys = 3;
    std::vector<BLS12_381::PrivateKey> private_keys(num_keys);
    std::vector<BLS12_381::PublicKey> public_keys(num_keys);
    std::vector<BLS12_381::Signature> signatures(num_keys);
    
    // 生成密钥对
    for (size_t i = 0; i < num_keys; ++i) {
        EXPECT_TRUE(bls->generate_private_key(private_keys[i]));
        EXPECT_TRUE(bls->derive_public_key(public_keys[i], private_keys[i]));
    }
    
    std::string message_str = "Aggregate signature test";
    BLS12_381::Message message(message_str.begin(), message_str.end());
    
    // 创建签名
    for (size_t i = 0; i < num_keys; ++i) {
        EXPECT_TRUE(bls->sign(signatures[i], message, private_keys[i]));
    }
    
    // 聚合签名
    BLS12_381::Signature aggregated_signature;
    EXPECT_TRUE(bls->aggregate_signatures(aggregated_signature, signatures));
    
    // 验证聚合签名
    EXPECT_TRUE(bls->verify_aggregated_same_message(aggregated_signature, message, public_keys));
}

// ========== 序列化测试 ==========

TEST_F(BLS12_381Test, HexSerialization) {
    BLS12_381::PrivateKey private_key;
    BLS12_381::PublicKey public_key;
    
    EXPECT_TRUE(bls->generate_private_key(private_key));
    EXPECT_TRUE(bls->derive_public_key(public_key, private_key));
    
    // 私钥序列化
    std::string private_hex = bls->private_key_to_hex(private_key);
    EXPECT_EQ(private_hex.length(), 64);  // 32字节 = 64个十六进制字符
    
    BLS12_381::PrivateKey private_key_restored;
    EXPECT_TRUE(bls->private_key_from_hex(private_key_restored, private_hex));
    EXPECT_EQ(private_key, private_key_restored);
}

// ========== 性能测试 ==========

TEST_F(BLS12_381Test, SigningPerformance) {
    BLS12_381::PrivateKey private_key;
    BLS12_381::PublicKey public_key;
    
    EXPECT_TRUE(bls->generate_private_key(private_key));
    EXPECT_TRUE(bls->derive_public_key(public_key, private_key));
    
    std::string message_str = "Performance test";
    BLS12_381::Message message(message_str.begin(), message_str.end());
    
    const int iterations = 10;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        BLS12_381::Signature signature;
        EXPECT_TRUE(bls->sign(signature, message, private_key));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / iterations;
    std::cout << "Average BLS12-381 signing time: " << avg_time << " μs" << std::endl;
    
    // BLS12-381签名比ECDSA慢，但应该在合理时间内
    EXPECT_LT(avg_time, 5000);  // 少于5ms
} 