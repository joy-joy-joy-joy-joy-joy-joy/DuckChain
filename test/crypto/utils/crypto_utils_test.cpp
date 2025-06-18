#include <gtest/gtest.h>
#include "crypto/utils/crypto_utils.hpp"

using namespace duckchain::crypto::utils;

class CryptoUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ========== 十六进制编码/解码测试 ==========

TEST_F(CryptoUtilsTest, HexEncodingDecoding) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    std::string expected_hex = "48656c6c6f";
    
    // 测试编码
    std::string hex = to_hex(data);
    EXPECT_EQ(hex, expected_hex);
    
    // 测试解码
    std::vector<uint8_t> decoded;
    EXPECT_TRUE(from_hex(decoded, hex));
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoUtilsTest, HexEncodingEmpty) {
    std::vector<uint8_t> empty_data;
    std::string hex = to_hex(empty_data);
    EXPECT_EQ(hex, "");
    
    std::vector<uint8_t> decoded;
    EXPECT_TRUE(from_hex(decoded, ""));
    EXPECT_TRUE(decoded.empty());
}

TEST_F(CryptoUtilsTest, HexDecodingInvalid) {
    std::vector<uint8_t> decoded;
    
    // 奇数长度
    EXPECT_FALSE(from_hex(decoded, "48656c6c6"));
    
    // 无效字符
    EXPECT_FALSE(from_hex(decoded, "48656g6c6f"));
}

TEST_F(CryptoUtilsTest, HexArrays) {
    std::array<uint8_t, 5> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::string hex = to_hex(data);
    EXPECT_EQ(hex, "48656c6c6f");
    
    std::array<uint8_t, 5> decoded;
    EXPECT_TRUE(from_hex(decoded, hex));
    EXPECT_EQ(decoded, data);
}

// ========== Base64编码/解码测试 ==========

TEST_F(CryptoUtilsTest, Base64EncodingDecoding) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    
    // 测试编码
    std::string base64 = to_base64(data);
    EXPECT_FALSE(base64.empty());
    
    // 测试解码
    std::vector<uint8_t> decoded;
    EXPECT_TRUE(from_base64(decoded, base64));
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoUtilsTest, Base64Empty) {
    std::vector<uint8_t> empty_data;
    std::string base64 = to_base64(empty_data);
    
    std::vector<uint8_t> decoded;
    EXPECT_TRUE(from_base64(decoded, base64));
    EXPECT_TRUE(decoded.empty());
}

// ========== 随机数生成测试 ==========

TEST_F(CryptoUtilsTest, SecureRandomBytes) {
    std::vector<uint8_t> random1(32);
    std::vector<uint8_t> random2(32);
    
    EXPECT_TRUE(secure_random_bytes(random1, 32));
    EXPECT_TRUE(secure_random_bytes(random2, 32));
    
    // 两个随机数应该不相同
    EXPECT_NE(random1, random2);
    
    // 长度应该正确
    EXPECT_EQ(random1.size(), 32);
    EXPECT_EQ(random2.size(), 32);
}

TEST_F(CryptoUtilsTest, SecureRandomArrays) {
    std::array<uint8_t, 32> random1;
    std::array<uint8_t, 32> random2;
    
    EXPECT_TRUE(secure_random_bytes(random1));
    EXPECT_TRUE(secure_random_bytes(random2));
    
    // 两个随机数应该不相同
    EXPECT_NE(random1, random2);
}

TEST_F(CryptoUtilsTest, SecureRandomIntegers) {
    uint32_t rand1 = secure_random_uint32();
    uint32_t rand2 = secure_random_uint32();
    
    // 基本上不可能相等
    EXPECT_NE(rand1, rand2);
    
    uint64_t rand64_1 = secure_random_uint64();
    uint64_t rand64_2 = secure_random_uint64();
    
    EXPECT_NE(rand64_1, rand64_2);
}

// ========== 哈希函数测试 ==========

TEST_F(CryptoUtilsTest, SHA256) {
    std::string message = "Hello, DuckChain!";
    auto hash = sha256(message);
    
    // SHA-256应该产生32字节哈希
    EXPECT_EQ(hash.size(), 32);
    
    // 相同输入应该产生相同哈希
    auto hash2 = sha256(message);
    EXPECT_EQ(hash, hash2);
    
    // 不同输入应该产生不同哈希
    auto hash3 = sha256("Different message");
    EXPECT_NE(hash, hash3);
}

TEST_F(CryptoUtilsTest, SHA256KnownVector) {
    // 空字符串的SHA-256
    std::string empty = "";
    auto hash = sha256(empty);
    
    // 已知的空字符串SHA-256哈希
    std::string expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::string actual_hex = to_hex(hash);
    
    EXPECT_EQ(actual_hex, expected_hex);
}

TEST_F(CryptoUtilsTest, SHA512) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto hash = sha512(data);
    
    // SHA-512应该产生64字节哈希
    EXPECT_EQ(hash.size(), 64);
    
    // 相同输入应该产生相同哈希
    auto hash2 = sha512(data);
    EXPECT_EQ(hash, hash2);
}

TEST_F(CryptoUtilsTest, BLAKE2b) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    
    auto hash256 = blake2b_256(data);
    auto hash512 = blake2b_512(data);
    
    EXPECT_EQ(hash256.size(), 32);
    EXPECT_EQ(hash512.size(), 64);
    
    // 相同输入应该产生相同哈希
    auto hash256_2 = blake2b_256(data);
    EXPECT_EQ(hash256, hash256_2);
}

// ========== 常数时间比较测试 ==========

TEST_F(CryptoUtilsTest, ConstantTimeEquals) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data3 = {0x01, 0x02, 0x03, 0x05};
    
    EXPECT_TRUE(constant_time_equals(data1, data2));
    EXPECT_FALSE(constant_time_equals(data1, data3));
    
    // 长度不同
    std::vector<uint8_t> data4 = {0x01, 0x02, 0x03};
    EXPECT_FALSE(constant_time_equals(data1, data4));
}

TEST_F(CryptoUtilsTest, ConstantTimeEqualsArrays) {
    std::array<uint8_t, 4> data1 = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 4> data2 = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 4> data3 = {0x01, 0x02, 0x03, 0x05};
    
    EXPECT_TRUE(constant_time_equals(data1, data2));
    EXPECT_FALSE(constant_time_equals(data1, data3));
}

// ========== 安全内存管理测试 ==========

TEST_F(CryptoUtilsTest, SecureZeroMemory) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    
    secure_zero_memory(data);
    
    for (auto byte : data) {
        EXPECT_EQ(byte, 0);
    }
}

TEST_F(CryptoUtilsTest, SecureZeroMemoryArray) {
    std::array<uint8_t, 4> data = {0x01, 0x02, 0x03, 0x04};
    
    secure_zero_memory(data);
    
    for (auto byte : data) {
        EXPECT_EQ(byte, 0);
    }
}

// ========== 性能测试 ==========

TEST_F(CryptoUtilsTest, HexEncodingPerformance) {
    std::vector<uint8_t> data(1024);
    secure_random_bytes(data, 1024);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 1000; ++i) {
        std::string hex = to_hex(data);
        (void)hex;  // 避免编译器优化
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // 1000次1KB编码应该在合理时间内完成（例如少于1秒）
    EXPECT_LT(duration.count(), 1000000);  // 小于1秒
}

TEST_F(CryptoUtilsTest, SHA256Performance) {
    std::vector<uint8_t> data(1024);
    secure_random_bytes(data, 1024);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 1000; ++i) {
        auto hash = sha256(data);
        (void)hash;  // 避免编译器优化
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // 1000次1KB哈希应该在合理时间内完成
    EXPECT_LT(duration.count(), 1000000);  // 小于1秒
} 