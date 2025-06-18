#include <gtest/gtest.h>
#include "crypto/core/ed25519.hpp"

using namespace duckchain::crypto;

class Ed25519Test : public ::testing::Test {
protected:
    void SetUp() override {
        ed25519 = std::make_unique<Ed25519>();
    }

    void TearDown() override {
        ed25519.reset();
    }

    std::unique_ptr<Ed25519> ed25519;
};

TEST_F(Ed25519Test, GenerateKeypair) {
    Ed25519::PrivateKey private_key;
    Ed25519::PublicKey public_key;
    
    EXPECT_TRUE(ed25519->generate_keypair(private_key, public_key));
    EXPECT_TRUE(ed25519->is_valid_private_key(private_key));
    EXPECT_TRUE(ed25519->is_valid_public_key(public_key));
}

TEST_F(Ed25519Test, SignAndVerify) {
    Ed25519::PrivateKey private_key;
    Ed25519::PublicKey public_key;
    EXPECT_TRUE(ed25519->generate_keypair(private_key, public_key));
    
    std::string message_str = "Hello, Ed25519!";
    Ed25519::Message message(message_str.begin(), message_str.end());
    Ed25519::Signature signature;
    
    EXPECT_TRUE(ed25519->sign(signature, message, private_key));
    EXPECT_TRUE(ed25519->verify(signature, message, public_key));
}

TEST_F(Ed25519Test, VerifyWithWrongMessage) {
    Ed25519::PrivateKey private_key;
    Ed25519::PublicKey public_key;
    EXPECT_TRUE(ed25519->generate_keypair(private_key, public_key));
    
    std::string message_str = "Original message";
    Ed25519::Message message(message_str.begin(), message_str.end());
    Ed25519::Signature signature;
    
    EXPECT_TRUE(ed25519->sign(signature, message, private_key));
    
    std::string wrong_message_str = "Wrong message";
    Ed25519::Message wrong_message(wrong_message_str.begin(), wrong_message_str.end());
    EXPECT_FALSE(ed25519->verify(signature, wrong_message, public_key));
} 