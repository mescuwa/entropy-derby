#pragma once

#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "secure_memory.hpp"

namespace it {

class RandomSource {
public:
    virtual ~RandomSource() = default;
    virtual double uniform01() = 0;
};

class InsecureTestRng : public RandomSource {
public:
    explicit InsecureTestRng(std::uint64_t seed);
    double uniform01() override;

private:
    std::mt19937_64 engine_;
    std::uniform_real_distribution<double> dist_;
};

using StdRng [[deprecated("StdRng has been renamed to InsecureTestRng and must not be used in production")]] =
    InsecureTestRng;

struct VrfKeyPair {
    std::string publicKeyHex;
    std::string secretKeyHex;
};

class ProvablyFairRng : public RandomSource {
public:
    ProvablyFairRng(std::string serverSecretKeyHex,
                    std::string serverPublicKeyHex,
                    std::string clientSeed,
                    std::uint64_t nonce,
                    std::string deploymentId,
                    std::string chainId = {});
    ProvablyFairRng(std::string vrfOutputHex,
                    std::string vrfProofHex,
                    std::string serverPublicKeyHex,
                    std::string clientSeed,
                    std::uint64_t nonce,
                    std::string deploymentId,
                    std::string chainId = {});
    ~ProvablyFairRng();

    double uniform01() override;

    static std::string hashSeed(const std::string& seed);
    static std::string buildAlpha(const std::string& deploymentId,
                                  const std::string& chainId,
                                  const std::string& clientSeed,
                                  std::uint64_t nonce);
    static bool verify(const std::string& vrfProofHex,
                       const std::string& vrfOutputHex,
                       const std::string& publicKeyHex,
                       const std::string& alpha);

    const std::string& getClientSeed() const { return clientSeed_; }
    const std::string& getAlpha() const { return alpha_; }
    const std::string& getDeploymentId() const { return deploymentId_; }
    const std::string& getChainId() const { return chainId_; }
    const std::string& getVrfProof() const { return vrfProofHex_; }
    const std::string& getVrfOutput() const { return vrfOutputHex_; }
    const std::string& getPublicKey() const { return publicKeyHex_; }
    std::uint64_t getNonce() const { return nonce_; }
    std::uint64_t getCallCount() const { return callCount_; }

private:
    std::array<std::uint8_t, 32> generateHash(std::uint64_t counter) const;

    std::string deploymentId_;
    std::string chainId_;
    std::string clientSeed_;
    std::string alpha_;
    std::string publicKeyHex_;
    SecureBuffer<unsigned char> secretKey_;
    std::vector<unsigned char> vrfProof_;
    std::vector<unsigned char> vrfOutput_;
    std::string vrfProofHex_;
    std::string vrfOutputHex_;
    std::uint64_t nonce_;
    std::uint64_t callCount_;
};

std::string generateServerSeed();
VrfKeyPair generateVrfKeypair();
VrfKeyPair deriveVrfKeypairFromSeed(const std::string& seedHex);

} // namespace it
