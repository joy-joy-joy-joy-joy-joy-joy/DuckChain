#include <gtest/gtest.h>
#include "crypto/core/ed25519.hpp"
#include <array>
#include <random>
#include <set>

using namespace duckchain::crypto;

class Ed25519Test : public ::testing::Test {
protected:
    void SetUp() override {
        ed25519 = std::make_unique<Ed25519>();
    }

    void TearDown() override {
        ed25519.reset();
    }

    // 生成随机消息
    Bytes generateRandomMessage(size_t length) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        Bytes message(length);
        for (auto& byte : message) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        return message;
    }

    std::unique_ptr<Ed25519> ed25519;
};

// 基本功能测试
TEST_F(Ed25519Test, KeyGeneration) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value()) << ed25519->getLastError();
    
    const auto& [priv_key, pub_key] = *key_pair;
    EXPECT_EQ(priv_key.size(), 32);
    EXPECT_EQ(pub_key.size(), 32);

    // 确保私钥不全为0
    bool all_zero = true;
    for (auto byte : priv_key) {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "Private key should not be all zeros";

    // 确保公钥不全为0
    all_zero = true;
    for (auto byte : pub_key) {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "Public key should not be all zeros";

    // 生成多个密钥对，确保它们都不相同
    auto another_key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(another_key_pair.has_value());
    EXPECT_NE(priv_key, another_key_pair->first) << "Different key pairs should have different private keys";
    EXPECT_NE(pub_key, another_key_pair->second) << "Different key pairs should have different public keys";
}

TEST_F(Ed25519Test, PublicKeyDerivation) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    auto derived_pub = ed25519->derivePublicKey(priv_key);
    
    ASSERT_TRUE(derived_pub.has_value()) << ed25519->getLastError();
    EXPECT_EQ(*derived_pub, pub_key);

    // 确保相同的私钥总是产生相同的公钥
    auto derived_pub2 = ed25519->derivePublicKey(priv_key);
    ASSERT_TRUE(derived_pub2.has_value());
    EXPECT_EQ(*derived_pub2, *derived_pub);
}

// 签名测试
TEST_F(Ed25519Test, SignAndVerify) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;

    // 测试不同长度的消息
    std::vector<size_t> message_lengths = {0, 1, 32, 64, 128, 1024};
    for (auto length : message_lengths) {
        Bytes message = generateRandomMessage(length);
        
        auto signature = ed25519->sign(message, priv_key);
        ASSERT_TRUE(signature.has_value()) << ed25519->getLastError();
        
        bool verified = ed25519->verify(message, *signature, pub_key);
        EXPECT_TRUE(verified) << "Failed to verify signature for message length " << length;
    }
}

// 错误处理测试
TEST_F(Ed25519Test, InvalidPrivateKey) {
    // 测试全0私钥
    Ed25519PrivateKey zero_key = {};
    auto pub_key = ed25519->derivePublicKey(zero_key);
    EXPECT_FALSE(pub_key.has_value()) << "Should fail with zero private key";
    EXPECT_FALSE(ed25519->getLastError().empty());

    // 测试签名
    Bytes message = {1, 2, 3};
    auto signature = ed25519->sign(message, zero_key);
    EXPECT_FALSE(signature.has_value()) << "Should fail to sign with zero private key";
    EXPECT_FALSE(ed25519->getLastError().empty());
}

TEST_F(Ed25519Test, InvalidPublicKey) {
    // 测试全0公钥
    Ed25519PublicKey zero_key = {};
    Bytes message = {1, 2, 3};
    Ed25519Signature fake_sig = {};
    bool verified = ed25519->verify(message, fake_sig, zero_key);
    EXPECT_FALSE(verified) << "Should fail to verify with zero public key";
    EXPECT_FALSE(ed25519->getLastError().empty());
}

// 签名修改测试
TEST_F(Ed25519Test, SignatureModification) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes message = {1, 2, 3, 4, 5};
    
    auto signature = ed25519->sign(message, priv_key);
    ASSERT_TRUE(signature.has_value());

    // 修改签名的每一个字节，确保验证失败
    auto modified_sig = *signature;
    for (size_t i = 0; i < modified_sig.size(); ++i) {
        modified_sig[i] ^= 0xFF;  // 翻转所有位
        bool verified = ed25519->verify(message, modified_sig, pub_key);
        EXPECT_FALSE(verified) << "Modified signature should not verify (byte " << i << ")";
        modified_sig[i] = (*signature)[i];  // 恢复原值
    }
}

// 消息修改测试
TEST_F(Ed25519Test, MessageModification) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes message = {1, 2, 3, 4, 5};
    
    auto signature = ed25519->sign(message, priv_key);
    ASSERT_TRUE(signature.has_value());
    
    // 修改消息的每一个字节
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] ^= 0xFF;  // 翻转所有位
        bool verified = ed25519->verify(message, *signature, pub_key);
        EXPECT_FALSE(verified) << "Modified message should not verify (byte " << i << ")";
        message[i] = i + 1;  // 恢复原值
    }
}

// 跨密钥验证测试
TEST_F(Ed25519Test, CrossKeyVerification) {
    auto key_pair1 = ed25519->generateKeyPair();
    auto key_pair2 = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair1.has_value());
    ASSERT_TRUE(key_pair2.has_value());

    Bytes message = {1, 2, 3, 4, 5};
    
    // 使用密钥对1签名
    auto signature = ed25519->sign(message, key_pair1->first);
    ASSERT_TRUE(signature.has_value());
    
    // 使用密钥对2的公钥验证，应该失败
    bool verified = ed25519->verify(message, *signature, key_pair2->second);
    EXPECT_FALSE(verified) << "Signature should not verify with different key pair";
}

// 性能测试
TEST_F(Ed25519Test, SigningPerformance) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    std::vector<Bytes> messages;
    
    // 准备不同大小的消息
    std::vector<size_t> message_sizes = {32, 64, 128, 256, 512, 1024};
    for (auto size : message_sizes) {
        messages.push_back(generateRandomMessage(size));
    }
    
    // 测试签名性能
    auto start = std::chrono::high_resolution_clock::now();
    for (const auto& message : messages) {
        auto signature = ed25519->sign(message, priv_key);
        ASSERT_TRUE(signature.has_value());
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << messages.size() << " Ed25519 signatures of various sizes took " 
              << duration.count() << "ms" << std::endl;
    
    // 测试验证性能
    start = std::chrono::high_resolution_clock::now();
    for (const auto& message : messages) {
        auto signature = ed25519->sign(message, priv_key);
        ASSERT_TRUE(signature.has_value());
        bool verified = ed25519->verify(message, *signature, pub_key);
        EXPECT_TRUE(verified);
    }
    end = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << messages.size() << " Ed25519 signature generations and verifications took " 
              << duration.count() << "ms" << std::endl;
}

// 空消息测试
TEST_F(Ed25519Test, EmptyMessage) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes empty_message;
    
    auto signature = ed25519->sign(empty_message, priv_key);
    ASSERT_TRUE(signature.has_value()) << "Should be able to sign empty message";
    
    bool verified = ed25519->verify(empty_message, *signature, pub_key);
    EXPECT_TRUE(verified) << "Should be able to verify empty message signature";
}

// 大消息测试
TEST_F(Ed25519Test, LargeMessage) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    Bytes large_message = generateRandomMessage(1024 * 1024);  // 1MB
    
    auto signature = ed25519->sign(large_message, priv_key);
    ASSERT_TRUE(signature.has_value()) << "Should be able to sign large message";
    
    bool verified = ed25519->verify(large_message, *signature, pub_key);
    EXPECT_TRUE(verified) << "Should be able to verify large message signature";
}

// 地址生成测试
TEST_F(Ed25519Test, AddressGeneration) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    const auto& [priv_key, pub_key] = *key_pair;
    auto address = ed25519->deriveAddress(pub_key);
    
    ASSERT_TRUE(address.has_value()) << ed25519->getLastError();
    EXPECT_EQ(address->size(), 20) << "Address should be 20 bytes";

    // 确保地址不全为0
    bool all_zero = true;
    for (auto byte : *address) {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "Address should not be all zeros";

    // 确保相同的公钥总是产生相同的地址
    auto address2 = ed25519->deriveAddress(pub_key);
    ASSERT_TRUE(address2.has_value());
    EXPECT_EQ(*address2, *address) << "Same public key should produce same address";

    // 确保不同的公钥产生不同的地址
    auto another_key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(another_key_pair.has_value());
    auto another_address = ed25519->deriveAddress(another_key_pair->second);
    ASSERT_TRUE(another_address.has_value());
    EXPECT_NE(*another_address, *address) << "Different public keys should produce different addresses";
}

TEST_F(Ed25519Test, AddressCollisionResistance) {
    // 生成多个地址并检查是否有冲突
    const size_t num_addresses = 1000;
    std::set<Ed25519Address> addresses;

    for (size_t i = 0; i < num_addresses; ++i) {
        auto key_pair = ed25519->generateKeyPair();
        ASSERT_TRUE(key_pair.has_value());
        
        auto address = ed25519->deriveAddress(key_pair->second);
        ASSERT_TRUE(address.has_value());
        
        // 检查这个地址是否已经存在
        auto [it, inserted] = addresses.insert(*address);
        EXPECT_TRUE(inserted) << "Found address collision";
    }

    EXPECT_EQ(addresses.size(), num_addresses) << "Should have " << num_addresses << " unique addresses";
}

TEST_F(Ed25519Test, InvalidAddressGeneration) {
    // 测试全0公钥
    Ed25519PublicKey zero_key = {};
    auto address = ed25519->deriveAddress(zero_key);
    EXPECT_FALSE(address.has_value()) << "Should fail with zero public key";
    EXPECT_FALSE(ed25519->getLastError().empty());
}

TEST_F(Ed25519Test, AddressFormat) {
    auto key_pair = ed25519->generateKeyPair();
    ASSERT_TRUE(key_pair.has_value());
    
    auto address = ed25519->deriveAddress(key_pair->second);
    ASSERT_TRUE(address.has_value());

    // 检查地址长度
    EXPECT_EQ(address->size(), 20) << "Address should be 20 bytes";

    // 检查地址是否包含有效的字节值
    for (auto byte : *address) {
        EXPECT_GE(byte, 0) << "Address byte should be >= 0";
        EXPECT_LE(byte, 255) << "Address byte should be <= 255";
    }
} 