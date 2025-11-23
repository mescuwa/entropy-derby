#include "timelock_encryption.hpp"

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

TimeLockEncryptor::TimeLockEncryptor(std::uint64_t iterations)
    : iterations_(iterations), raceLock_(nullptr) {
    if (iterations_ == 0) {
        throw std::invalid_argument("TimeLockEncryptor requires positive iterations");
    }
    if (!ensureSodiumReady()) {
        throw std::runtime_error("Unable to initialize libsodium for timelock encryption");
    }
}

void TimeLockEncryptor::initializeRace(const std::string& contextLabel) {
    if (raceLock_) {
        throw std::runtime_error("Race already initialized");
    }
    raceLock_ = std::make_unique<RaceLevelTimeLock>(iterations_);
    raceLock_->initialize(contextLabel);
}

RaceLevelTimeLockParams TimeLockEncryptor::getRaceParams() const {
    if (!raceLock_) {
        throw std::runtime_error("Race not initialized");
    }
    return raceLock_->exportParams();
}

void TimeLockEncryptor::importRaceParams(const RaceLevelTimeLockParams& params) {
    if (raceLock_) {
        throw std::runtime_error("Cannot import params into already initialized race");
    }
    raceLock_ = std::make_unique<RaceLevelTimeLock>(iterations_);
    raceLock_->importParams(params);
}

TimeLockedCiphertext TimeLockEncryptor::encrypt(const std::string& plaintext,
                                                const std::string& contextLabel) {
    if (!raceLock_) {
        throw std::runtime_error("Race not initialized; call initializeRace() first");
    }

    // Use race-level public-key encryption (fast, no VDF)
    std::string ciphertextHex = raceLock_->encrypt(plaintext);

    TimeLockedCiphertext out;
    out.ciphertextHex = ciphertextHex;
    out.iterations = iterations_;
    // Deprecated fields left empty
    out.puzzlePreimage = "";
    out.nonceHex = "";
    return out;
}

std::optional<std::string> TimeLockEncryptor::decrypt(const TimeLockedCiphertext& ciph) const {
    if (!ensureSodiumReady()) {
        return std::nullopt;
    }
    if (!raceLock_) {
        return std::nullopt;
    }
    if (ciph.iterations != iterations_) {
        return std::nullopt;
    }

    // Race key must be unlocked before decryption
    // Caller must explicitly call unlockRaceKey() first
    if (!raceLock_->isUnlocked()) {
        return std::nullopt;
    }

    // Decrypt using unlocked private key (fast)
    return raceLock_->decrypt(ciph.ciphertextHex);
}

bool TimeLockEncryptor::unlockRaceKey() {
    if (!raceLock_) {
        return false;
    }
    return raceLock_->unlockSecretKey();
}

bool TimeLockEncryptor::isRaceKeyUnlocked() const {
    if (!raceLock_) {
        return false;
    }
    return raceLock_->isUnlocked();
}

std::vector<unsigned char> TimeLockEncryptor::hexToBytes(const std::string& hex) const {
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

std::string TimeLockEncryptor::bytesToHex(const unsigned char* data, std::size_t len) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string TimeLockEncryptor::deriveKey(const std::string& preimage) const {
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(preimage.begin(), preimage.end(), hash.begin(), hash.end());
    return bytesToHex(hash.data(), hash.size());
}

} // namespace it
