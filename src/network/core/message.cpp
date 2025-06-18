#include "message.hpp"
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace duckchain {
namespace network {

Message::Message(MessageType type, const std::vector<uint8_t>& payload)
    : type_(type), payload_(payload) {}

Message::Message(MessageType type, std::vector<uint8_t>&& payload)
    : type_(type), payload_(std::move(payload)) {}

std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> result;
    // Reserve space for the header (1 byte type + 4 bytes size)
    result.reserve(5 + payload_.size());
    
    // Write message type
    result.push_back(static_cast<uint8_t>(type_));
    
    // Write payload size (4 bytes, big endian)
    uint32_t size = getSize();
    result.push_back(static_cast<uint8_t>((size >> 24) & 0xFF));
    result.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(size & 0xFF));
    
    // Write payload
    result.insert(result.end(), payload_.begin(), payload_.end());
    
    return result;
}

std::shared_ptr<Message> Message::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        throw std::runtime_error("Invalid message: too short");
    }
    
    // Read message type
    MessageType type = static_cast<MessageType>(data[0]);
    
    // Read payload size
    uint32_t size = (static_cast<uint32_t>(data[1]) << 24) |
                    (static_cast<uint32_t>(data[2]) << 16) |
                    (static_cast<uint32_t>(data[3]) << 8) |
                    static_cast<uint32_t>(data[4]);
    
    if (data.size() != size + 5) {
        throw std::runtime_error("Invalid message: size mismatch");
    }
    
    // Extract payload
    std::vector<uint8_t> payload(data.begin() + 5, data.end());
    
    return std::make_shared<Message>(type, std::move(payload));
}

std::string Message::toString() const {
    std::stringstream ss;
    ss << "Message{type=0x" << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(type_) << ", size=" << std::dec << getSize() << "}";
    return ss.str();
}

bool Message::isValid() const {
    // Basic validation
    if (payload_.size() > 1024 * 1024) { // Max 1MB payload
        return false;
    }
    
    // Type validation
    switch (type_) {
        case MessageType::HANDSHAKE:
        case MessageType::PING:
        case MessageType::PONG:
        case MessageType::DISCOVERY:
        case MessageType::SERVICE_ANNOUNCEMENT:
        case MessageType::DATA:
        case MessageType::REQUEST:
        case MessageType::RESPONSE:
            return true;
        default:
            return false;
    }
}

} // namespace network
} // namespace duckchain 