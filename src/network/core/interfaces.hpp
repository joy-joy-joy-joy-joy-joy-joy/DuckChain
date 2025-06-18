#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <future>

namespace duckchain {
namespace network {

// Forward declarations
class Message;
class Peer;
class NetworkConfig;

/**
 * @brief Interface for network nodes
 */
class INode {
public:
    virtual ~INode() = default;
    
    // Basic node operations
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual bool isRunning() const = 0;
    
    // Peer management
    virtual std::vector<std::shared_ptr<Peer>> getPeers() const = 0;
    virtual bool connectToPeer(const std::string& address) = 0;
    virtual void disconnectPeer(const std::string& peerId) = 0;
    
    // Message handling
    virtual bool broadcast(const Message& message) = 0;
    virtual bool sendTo(const std::string& peerId, const Message& message) = 0;
    virtual void subscribe(std::function<void(const Message&, const std::string&)> callback) = 0;
};

/**
 * @brief Interface for service discovery
 */
class IDiscovery {
public:
    virtual ~IDiscovery() = default;
    
    virtual bool start() = 0;
    virtual void stop() = 0;
    virtual std::vector<std::string> discoverPeers() = 0;
    virtual void advertiseService(const std::string& serviceName, uint16_t port) = 0;
};

/**
 * @brief Interface for transport layer
 */
class ITransport {
public:
    virtual ~ITransport() = default;
    
    virtual bool listen(uint16_t port) = 0;
    virtual void close() = 0;
    virtual bool send(const std::string& address, const std::vector<uint8_t>& data) = 0;
    virtual void setMessageHandler(std::function<void(const std::vector<uint8_t>&, const std::string&)> handler) = 0;
};

} // namespace network
} // namespace duckchain 