#include <gtest/gtest.h>
#include "network/core/message.hpp"
#include <vector>
#include <stdexcept>

using namespace duckchain::network;

class MessageTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Test data
        testPayload = {0x01, 0x02, 0x03, 0x04, 0x05};
    }
    
    std::vector<uint8_t> testPayload;
};

TEST_F(MessageTest, Constructor) {
    Message msg(MessageType::DATA, testPayload);
    EXPECT_EQ(msg.getType(), MessageType::DATA);
    EXPECT_EQ(msg.getPayload(), testPayload);
    EXPECT_EQ(msg.getSize(), testPayload.size());
}

TEST_F(MessageTest, Serialization) {
    Message original(MessageType::DATA, testPayload);
    std::vector<uint8_t> serialized = original.serialize();
    
    // Verify serialized format
    EXPECT_EQ(serialized.size(), 5 + testPayload.size()); // Header + payload
    EXPECT_EQ(serialized[0], static_cast<uint8_t>(MessageType::DATA));
    
    // Size bytes (big endian)
    EXPECT_EQ(serialized[1], 0x00);
    EXPECT_EQ(serialized[2], 0x00);
    EXPECT_EQ(serialized[3], 0x00);
    EXPECT_EQ(serialized[4], 0x05);
    
    // Payload
    for (size_t i = 0; i < testPayload.size(); i++) {
        EXPECT_EQ(serialized[i + 5], testPayload[i]);
    }
}

TEST_F(MessageTest, Deserialization) {
    Message original(MessageType::DATA, testPayload);
    std::vector<uint8_t> serialized = original.serialize();
    
    auto deserialized = Message::deserialize(serialized);
    EXPECT_EQ(deserialized->getType(), original.getType());
    EXPECT_EQ(deserialized->getPayload(), original.getPayload());
    EXPECT_EQ(deserialized->getSize(), original.getSize());
}

TEST_F(MessageTest, InvalidDeserialization) {
    // Too short
    std::vector<uint8_t> tooShort = {0x01, 0x02, 0x03};
    EXPECT_THROW(Message::deserialize(tooShort), std::runtime_error);
    
    // Size mismatch
    std::vector<uint8_t> sizeMismatch = {
        0x01, // type
        0x00, 0x00, 0x00, 0x0A, // size (10 bytes)
        0x01, 0x02, 0x03 // only 3 bytes
    };
    EXPECT_THROW(Message::deserialize(sizeMismatch), std::runtime_error);
}

TEST_F(MessageTest, Validation) {
    // Valid message
    Message valid(MessageType::DATA, testPayload);
    EXPECT_TRUE(valid.isValid());
    
    // Invalid type
    Message invalid(static_cast<MessageType>(0xFF), testPayload);
    EXPECT_FALSE(invalid.isValid());
    
    // Too large payload
    std::vector<uint8_t> largePayload(1024 * 1024 + 1, 0x00);
    Message tooLarge(MessageType::DATA, largePayload);
    EXPECT_FALSE(tooLarge.isValid());
}

TEST_F(MessageTest, ToString) {
    Message msg(MessageType::DATA, testPayload);
    std::string str = msg.toString();
    EXPECT_TRUE(str.find("type=0x06") != std::string::npos);
    EXPECT_TRUE(str.find("size=5") != std::string::npos);
} 