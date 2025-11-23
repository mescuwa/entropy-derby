#pragma once

#include "race_timelock.hpp"
#include "vdf.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace it {

// Ciphertext encrypted with race-level timelock
// Uses public-key encryption; no per-bet VDF required
struct TimeLockedCiphertext {
    std::string ciphertextHex;        // crypto_box_seal output
    std::uint64_t iterations = 0;     // VDF iterations (for compatibility)

    // Deprecated fields (kept for backward compatibility, always empty)
    std::string puzzlePreimage;
    std::string nonceHex;
};

// TimeLockEncryptor now uses race-level timelock architecture
// - One VDF per race (not per bet)
// - Public-key encryption for bets (fast)
// - VDF-protected private key enables batch decryption
class TimeLockEncryptor {
public:
    explicit TimeLockEncryptor(std::uint64_t iterations);

    // Initialize the race-level timelock
    // Must be called before encrypt() or decrypt()
    // contextLabel: unique identifier for this race
    void initializeRace(const std::string& contextLabel);

    // Get the race-level timelock parameters (for transparency)
    RaceLevelTimeLockParams getRaceParams() const;

    // Import race parameters (for decryption without initialization)
    void importRaceParams(const RaceLevelTimeLockParams& params);

    // Encrypt plaintext using race public key (fast, no VDF)
    TimeLockedCiphertext encrypt(const std::string& plaintext,
                                 const std::string& contextLabel = "bet");

    // Decrypt ciphertext using VDF-unlocked private key
    // First call triggers VDF evaluation (expensive)
    // Subsequent calls use cached private key (fast)
    std::optional<std::string> decrypt(const TimeLockedCiphertext& ciph) const;

    // Manually unlock the race private key (solve VDF)
    // Returns true if successful or already unlocked
    bool unlockRaceKey();

    // Check if race key is unlocked
    bool isRaceKeyUnlocked() const;

private:
    std::uint64_t iterations_;
    mutable std::unique_ptr<RaceLevelTimeLock> raceLock_;

    std::vector<unsigned char> hexToBytes(const std::string& hex) const;
    std::string bytesToHex(const unsigned char* data, std::size_t len) const;
    std::string deriveKey(const std::string& preimage) const;
};

} // namespace it

