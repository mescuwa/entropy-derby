#include "rng.hpp"

#include "picosha2.h"
#include "secure_memory.hpp"
#include "secure_random.hpp"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace it {

#ifndef crypto_vrf_PROOFBYTES
#error "libsodium must provide crypto_vrf_* support (version >= 1.0.18)"
#endif

namespace {

bool ensureSodiumReady() {
    static bool ready = sodium_init() >= 0;
    return ready;
}

std::string bytesToHex(const unsigned char* data, std::size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string must have even length");
    }

    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned int byte = 0;
        std::istringstream iss(byteString);
        iss >> std::hex >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

std::string buildDeploymentScope(const std::string& deploymentId, const std::string& chainId) {
    if (deploymentId.empty()) {
        throw std::invalid_argument("deploymentId must not be empty for VRF domain separation");
    }
    if (chainId.empty()) {
        return deploymentId;
    }
    std::ostringstream oss;
    oss << deploymentId << "|" << chainId;
    return oss.str();
}

constexpr std::string_view kVrfDomainTag = "entropy-derby:vrf:v2";

} // namespace

std::string ProvablyFairRng::buildAlpha(const std::string& deploymentId,
                                        const std::string& chainId,
                                        const std::string& clientSeed,
                                        std::uint64_t nonce) {
    std::ostringstream oss;
    oss << kVrfDomainTag << "|" << buildDeploymentScope(deploymentId, chainId) << "|" << clientSeed
        << ":" << nonce;
    return oss.str();
}

InsecureTestRng::InsecureTestRng(std::uint64_t seed)
    : engine_(seed)
    , dist_(0.0, 1.0) {}

double InsecureTestRng::uniform01() {
    return dist_(engine_);
}

ProvablyFairRng::ProvablyFairRng(std::string serverSecretKeyHex,
                                 std::string serverPublicKeyHex,
                                 std::string clientSeed,
                                 std::uint64_t nonce,
                                 std::string deploymentId,
                                 std::string chainId)
    : deploymentId_(std::move(deploymentId))
    , chainId_(std::move(chainId))
    , clientSeed_(std::move(clientSeed))
    , alpha_(buildAlpha(deploymentId_, chainId_, clientSeed_, nonce))
    , publicKeyHex_(std::move(serverPublicKeyHex))
    , nonce_(nonce)
    , callCount_(0) {
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium");
    }

    auto secretBytes = hexToBytes(serverSecretKeyHex);
    secureZero(serverSecretKeyHex.data(), serverSecretKeyHex.size());
    if (secretBytes.size() != crypto_vrf_SECRETKEYBYTES) {
        secureZero(secretBytes.data(), secretBytes.size());
        throw std::invalid_argument("server secret key length invalid");
    }
    secretKey_.resize(secretBytes.size());
    std::copy(secretBytes.begin(), secretBytes.end(), secretKey_.data());
    secureZero(secretBytes.data(), secretBytes.size());

    auto publicKey = hexToBytes(publicKeyHex_);
    if (publicKey.size() != crypto_vrf_PUBLICKEYBYTES) {
        throw std::invalid_argument("server public key length invalid");
    }

    vrfProof_.resize(crypto_vrf_PROOFBYTES);
    if (crypto_vrf_prove(vrfProof_.data(),
                         secretKey_.data(),
                         reinterpret_cast<const unsigned char*>(alpha_.data()),
                         alpha_.size()) != 0) {
        throw std::runtime_error("VRF prove failed");
    }

    vrfOutput_.resize(crypto_vrf_OUTPUTBYTES);
    if (crypto_vrf_proof_to_hash(vrfOutput_.data(), vrfProof_.data()) != 0) {
        throw std::runtime_error("VRF hash extraction failed");
    }

    std::vector<unsigned char> verified(crypto_vrf_OUTPUTBYTES);
    if (crypto_vrf_verify(verified.data(),
                          publicKey.data(),
                          vrfProof_.data(),
                          reinterpret_cast<const unsigned char*>(alpha_.data()),
                          alpha_.size()) != 0) {
        throw std::runtime_error("VRF proof does not verify with provided public key");
    }
    if (!std::equal(verified.begin(), verified.end(), vrfOutput_.begin())) {
        throw std::runtime_error("VRF output mismatch after verification");
    }

    vrfProofHex_ = bytesToHex(vrfProof_.data(), vrfProof_.size());
    vrfOutputHex_ = bytesToHex(vrfOutput_.data(), vrfOutput_.size());
}

ProvablyFairRng::ProvablyFairRng(std::string vrfOutputHex,
                                 std::string vrfProofHex,
                                 std::string serverPublicKeyHex,
                                 std::string clientSeed,
                                 std::uint64_t nonce,
                                 std::string deploymentId,
                                 std::string chainId)
    : deploymentId_(std::move(deploymentId))
    , chainId_(std::move(chainId))
    , clientSeed_(std::move(clientSeed))
    , alpha_(buildAlpha(deploymentId_, chainId_, clientSeed_, nonce))
    , publicKeyHex_(std::move(serverPublicKeyHex))
    , secretKey_()
    , vrfProofHex_(std::move(vrfProofHex))
    , vrfOutputHex_(std::move(vrfOutputHex))
    , nonce_(nonce)
    , callCount_(0) {
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium");
    }

    vrfProof_ = hexToBytes(vrfProofHex_);
    vrfOutput_ = hexToBytes(vrfOutputHex_);
    auto publicKey = hexToBytes(publicKeyHex_);

    if (vrfProof_.size() != crypto_vrf_PROOFBYTES ||
        vrfOutput_.size() != crypto_vrf_OUTPUTBYTES ||
        publicKey.size() != crypto_vrf_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid VRF artifact length");
    }

    std::vector<unsigned char> recomputed(crypto_vrf_OUTPUTBYTES);
    if (crypto_vrf_verify(recomputed.data(),
                          publicKey.data(),
                          vrfProof_.data(),
                          reinterpret_cast<const unsigned char*>(alpha_.data()),
                          alpha_.size()) != 0) {
        throw std::runtime_error("VRF proof rejected for provided public key");
    }

    if (!std::equal(recomputed.begin(), recomputed.end(), vrfOutput_.begin())) {
        throw std::runtime_error("VRF output mismatch");
    }

    vrfProofHex_ = bytesToHex(vrfProof_.data(), vrfProof_.size());
    vrfOutputHex_ = bytesToHex(vrfOutput_.data(), vrfOutput_.size());
}

ProvablyFairRng::~ProvablyFairRng() {
    secureZero(secretKey_.data(), secretKey_.size());
    secureZero(vrfProof_.data(), vrfProof_.size());
    secureZero(vrfOutput_.data(), vrfOutput_.size());
    std::fill(deploymentId_.begin(), deploymentId_.end(), '\0');
    std::fill(chainId_.begin(), chainId_.end(), '\0');
    std::fill(clientSeed_.begin(), clientSeed_.end(), '\0');
    std::fill(alpha_.begin(), alpha_.end(), '\0');
    std::fill(publicKeyHex_.begin(), publicKeyHex_.end(), '\0');
    std::fill(vrfProofHex_.begin(), vrfProofHex_.end(), '\0');
    std::fill(vrfOutputHex_.begin(), vrfOutputHex_.end(), '\0');
}

std::string ProvablyFairRng::hashSeed(const std::string& seed) {
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(seed.begin(), seed.end(), hash.begin(), hash.end());
    return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}

bool ProvablyFairRng::verify(const std::string& vrfProofHex,
                             const std::string& vrfOutputHex,
                             const std::string& publicKeyHex,
                             const std::string& alpha) {
    if (!ensureSodiumReady()) {
        return false;
    }

    try {
        auto proof = hexToBytes(vrfProofHex);
        auto publicKey = hexToBytes(publicKeyHex);
        auto output = hexToBytes(vrfOutputHex);
        if (proof.size() != crypto_vrf_PROOFBYTES ||
            output.size() != crypto_vrf_OUTPUTBYTES ||
            publicKey.size() != crypto_vrf_PUBLICKEYBYTES) {
            return false;
        }

        std::vector<unsigned char> recomputed(crypto_vrf_OUTPUTBYTES);
        if (crypto_vrf_verify(recomputed.data(),
                              publicKey.data(),
                              proof.data(),
                              reinterpret_cast<const unsigned char*>(alpha.data()),
                              alpha.size()) != 0) {
            return false;
        }

        return std::equal(recomputed.begin(), recomputed.end(), output.begin());
    } catch (const std::exception&) {
        return false;
    }
}

std::array<std::uint8_t, 32> ProvablyFairRng::generateHash(std::uint64_t counter) const {
    std::ostringstream oss;
    oss << kVrfDomainTag << "|" << buildDeploymentScope(deploymentId_, chainId_) << "|"
        << vrfOutputHex_ << ':' << clientSeed_ << ':' << nonce_ << ':' << counter;
    std::string input = oss.str();

    std::array<std::uint8_t, 32> hash{};
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
    return hash;
}

double ProvablyFairRng::uniform01() {
    auto hash = generateHash(callCount_++);

    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | hash[i];
    }

    const std::uint64_t mask = (1ULL << 53) - 1;
    val &= mask;
    return static_cast<double>(val) / static_cast<double>(1ULL << 53);
}

std::string generateServerSeed() {
    // 32 bytes of entropy renders a 64-character hex seed.
    return secureRandomHex(32);
}

VrfKeyPair generateVrfKeypair() {
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium");
    }

    std::vector<unsigned char> publicKey(crypto_vrf_PUBLICKEYBYTES);
    std::vector<unsigned char> secretKey(crypto_vrf_SECRETKEYBYTES);
    crypto_vrf_keypair(publicKey.data(), secretKey.data());

    VrfKeyPair pair{
        bytesToHex(publicKey.data(), publicKey.size()),
        bytesToHex(secretKey.data(), secretKey.size()),
    };

    secureZero(secretKey.data(), secretKey.size());
    return pair;
}

VrfKeyPair deriveVrfKeypairFromSeed(const std::string& seedHex) {
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium");
    }

    auto seed = hexToBytes(seedHex);
    if (seed.size() != crypto_vrf_SEEDBYTES) {
        throw std::invalid_argument("Seed must decode to crypto_vrf_SEEDBYTES bytes");
    }

    std::vector<unsigned char> publicKey(crypto_vrf_PUBLICKEYBYTES);
    std::vector<unsigned char> secretKey(crypto_vrf_SECRETKEYBYTES);
    if (crypto_vrf_keypair_from_seed(publicKey.data(), secretKey.data(), seed.data()) != 0) {
        throw std::runtime_error("Failed to derive VRF keypair from seed");
    }

    VrfKeyPair pair{
        bytesToHex(publicKey.data(), publicKey.size()),
        bytesToHex(secretKey.data(), secretKey.size()),
    };
    secureZero(secretKey.data(), secretKey.size());
    return pair;
}

} // namespace it
