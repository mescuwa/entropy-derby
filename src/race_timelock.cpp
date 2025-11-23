#include "race_timelock.hpp"

#include "picosha2.h"

#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <sodium.h>

namespace it {
namespace {

bool ensureSodiumReady() {
    static bool ready = sodium_init() >= 0;
    return ready;
}

} // namespace

RaceLevelTimeLock::RaceLevelTimeLock(std::uint64_t vdfIterations)
    : vdfIterations_(vdfIterations) {
    if (vdfIterations_ == 0) {
        throw std::invalid_argument("RaceLevelTimeLock requires positive VDF iterations");
    }
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium for race-level timelock");
    }
}

void RaceLevelTimeLock::initialize(const std::string& contextLabel) {
    if (initialized_) {
        throw std::runtime_error("RaceLevelTimeLock already initialized");
    }
    if (contextLabel.empty()) {
        throw std::invalid_argument("contextLabel must not be empty");
    }

    contextLabel_ = contextLabel;

    // Generate ephemeral keypair for this race
    publicKey_.resize(crypto_box_PUBLICKEYBYTES);
    std::vector<unsigned char> tempSecretKey(crypto_box_SECRETKEYBYTES);
    if (crypto_box_keypair(publicKey_.data(), tempSecretKey.data()) != 0) {
        throw std::runtime_error("Failed to generate keypair");
    }

    // Generate VDF puzzle: hash context + random seed
    std::vector<unsigned char> randomSeed(32);
    randombytes_buf(randomSeed.data(), randomSeed.size());
    std::ostringstream puzzleBuilder;
    puzzleBuilder << contextLabel << ":" << bytesToHex(randomSeed.data(), randomSeed.size());
    puzzlePreimage_ = puzzleBuilder.str();

    // Evaluate VDF to derive encryption key for secret key
    WesolowskiVdf vdf(vdfIterations_);
    VdfResult vdfResult = vdf.evaluate(puzzlePreimage_);

    // Encrypt the secret key using VDF-derived key
    // Derive encryption key from VDF output
    std::string keyHex = deriveKeyFromVdf(vdfResult.outputHex);
    std::vector<unsigned char> key = hexToBytes(keyHex);

    // Generate nonce for secret key encryption
    encryptedSecretNonce_.resize(crypto_secretbox_NONCEBYTES);
    randombytes_buf(encryptedSecretNonce_.data(), encryptedSecretNonce_.size());

    // Encrypt the secret key
    encryptedSecretKey_.resize(crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(encryptedSecretKey_.data(),
                              tempSecretKey.data(),
                              tempSecretKey.size(),
                              encryptedSecretNonce_.data(),
                              key.data()) != 0) {
        sodium_memzero(tempSecretKey.data(), tempSecretKey.size());
        throw std::runtime_error("Failed to encrypt secret key");
    }

    // Clear temporary secret key from memory
    sodium_memzero(tempSecretKey.data(), tempSecretKey.size());

    initialized_ = true;
}

std::string RaceLevelTimeLock::getPublicKeyHex() const {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }
    return bytesToHex(publicKey_.data(), publicKey_.size());
}

std::string RaceLevelTimeLock::getPuzzlePreimage() const {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }
    return puzzlePreimage_;
}

std::string RaceLevelTimeLock::getEncryptedSecretKeyHex() const {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }
    return bytesToHex(encryptedSecretKey_.data(), encryptedSecretKey_.size());
}

std::string RaceLevelTimeLock::getEncryptedSecretNonceHex() const {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }
    return bytesToHex(encryptedSecretNonce_.data(), encryptedSecretNonce_.size());
}

RaceLevelTimeLockParams RaceLevelTimeLock::exportParams() const {
    RaceLevelTimeLockParams params;
    params.publicKeyHex = getPublicKeyHex();
    params.puzzlePreimage = getPuzzlePreimage();
    params.encryptedSecretKeyHex = getEncryptedSecretKeyHex();
    params.encryptedSecretNonceHex = getEncryptedSecretNonceHex();
    params.vdfIterations = vdfIterations_;
    return params;
}

void RaceLevelTimeLock::importParams(const RaceLevelTimeLockParams& params) {
    if (initialized_) {
        throw std::runtime_error("Cannot import into already initialized RaceLevelTimeLock");
    }
    if (params.vdfIterations == 0) {
        throw std::invalid_argument("Invalid VDF iterations in imported params");
    }

    vdfIterations_ = params.vdfIterations;
    puzzlePreimage_ = params.puzzlePreimage;
    publicKey_ = hexToBytes(params.publicKeyHex);
    encryptedSecretKey_ = hexToBytes(params.encryptedSecretKeyHex);
    encryptedSecretNonce_ = hexToBytes(params.encryptedSecretNonceHex);

    if (publicKey_.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid public key size in imported params");
    }
    if (encryptedSecretNonce_.size() != crypto_secretbox_NONCEBYTES) {
        throw std::invalid_argument("Invalid nonce size in imported params");
    }

    initialized_ = true;
    unlocked_ = false;
}

bool RaceLevelTimeLock::unlockSecretKey() {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }
    if (unlocked_) {
        return true; // Already unlocked
    }

    // Solve the VDF puzzle (expensive operation)
    WesolowskiVdf vdf(vdfIterations_);
    VdfResult vdfResult = vdf.evaluate(puzzlePreimage_);

    // Decrypt the secret key using VDF-derived key
    if (!decryptSecretKeyWithVdf(vdfResult.outputHex)) {
        return false;
    }

    unlocked_ = true;
    return true;
}

bool RaceLevelTimeLock::isUnlocked() const {
    return unlocked_;
}

std::string RaceLevelTimeLock::encrypt(const std::string& plaintext) const {
    if (!initialized_) {
        throw std::runtime_error("RaceLevelTimeLock not initialized");
    }

    // Use crypto_box_seal for anonymous public-key encryption
    // Output is crypto_box_SEALBYTES + plaintext.size()
    std::vector<unsigned char> ciphertext(crypto_box_SEALBYTES + plaintext.size());
    if (crypto_box_seal(ciphertext.data(),
                        reinterpret_cast<const unsigned char*>(plaintext.data()),
                        plaintext.size(),
                        publicKey_.data()) != 0) {
        throw std::runtime_error("crypto_box_seal failed");
    }

    return bytesToHex(ciphertext.data(), ciphertext.size());
}

std::optional<std::string> RaceLevelTimeLock::decrypt(const std::string& ciphertextHex) const {
    if (!initialized_) {
        return std::nullopt;
    }
    if (!unlocked_) {
        return std::nullopt; // Secret key not available
    }

    std::vector<unsigned char> ciphertext = hexToBytes(ciphertextHex);
    if (ciphertext.size() < crypto_box_SEALBYTES) {
        return std::nullopt;
    }

    std::vector<unsigned char> plaintext(ciphertext.size() - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(plaintext.data(),
                             ciphertext.data(),
                             ciphertext.size(),
                             publicKey_.data(),
                             secretKey_.data()) != 0) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}

std::vector<unsigned char> RaceLevelTimeLock::hexToBytes(const std::string& hex) const {
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
        if (iss.fail()) {
            throw std::invalid_argument("Invalid hex string");
        }
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

std::string RaceLevelTimeLock::bytesToHex(const unsigned char* data, std::size_t len) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string RaceLevelTimeLock::deriveKeyFromVdf(const std::string& vdfOutput) const {
    // Derive a 256-bit key from VDF output using SHA-256
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(vdfOutput.begin(), vdfOutput.end(), hash.begin(), hash.end());
    return bytesToHex(hash.data(), hash.size());
}


bool RaceLevelTimeLock::decryptSecretKeyWithVdf(const std::string& vdfOutput) {
    // Derive decryption key from VDF output
    std::string keyHex = deriveKeyFromVdf(vdfOutput);
    std::vector<unsigned char> key = hexToBytes(keyHex);

    if (encryptedSecretKey_.size() < crypto_secretbox_MACBYTES) {
        return false;
    }

    // Decrypt the secret key
    secretKey_.resize(crypto_box_SECRETKEYBYTES);
    if (crypto_secretbox_open_easy(secretKey_.data(),
                                   encryptedSecretKey_.data(),
                                   encryptedSecretKey_.size(),
                                   encryptedSecretNonce_.data(),
                                   key.data()) != 0) {
        secretKey_.clear();
        return false;
    }

    return true;
}

} // namespace it
