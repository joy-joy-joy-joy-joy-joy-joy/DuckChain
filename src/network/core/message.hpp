#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace duckchain {
namespace network {

enum class MessageType : uint8_t {
    HANDSHAKE = 0x01,
    PING = 0x02,
    PONG = 0x03,
    DISCOVERY = 0x04,
    SERVICE_ANNOUNCEMENT = 0x05,
    DATA = 0x06,
    REQUEST = 0x07,
    RESPONSE = 0x08
};

class Message {
public:
    Message() = default;
    Message(MessageType type, const std::vector<uint8_t>& payload);
    Message(MessageType type, std::vector<uint8_t>&& payload);
    
    // Getters
    MessageType getType() const { return type_; }
    const std::vector<uint8_t>& getPayload() const { return payload_; }
    uint32_t getSize() const { return static_cast<uint32_t>(payload_.size()); }
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    static std::shared_ptr<Message> deserialize(const std::vector<uint8_t>& data);
    
    // Utility methods
    std::string toString() const;
    bool isValid() const;
    
private:
    MessageType type_{MessageType::DATA};
    std::vector<uint8_t> payload_;
};

} // namespace network
} // namespace duckchain 