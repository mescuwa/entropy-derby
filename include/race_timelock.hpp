#pragma once

#include "vdf.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace it {

// Parameters for a race-level timelock, enabling public-key encryption
// with VDF-protected secret key.
struct RaceLevelTimeLockParams {
    std::string publicKeyHex;            // Public key for bet encryption (32 bytes hex)
    std::string puzzlePreimage;          // VDF puzzle input
    std::uint64_t vdfIterations = 0;     // VDF difficulty

    // Internal-only VDF solution/proof exported for engine-side verification flows.
    std::string vdfOutputHex;
    std::string vdfProofHex;

    std::string encryptedSecretKeyHex;   // Secret key encrypted with VDF-derived key
    std::string encryptedSecretNonceHex; // Nonce for secret key encryption
};

// Race-level timelock: one VDF puzzle protects the decryption key for all bets in a race.
//
// Security model:
// - House generates ephemeral keypair (pk, sk) at race start
// - House encrypts sk using key derived from VDF puzzle
// - Bettors encrypt their bets using pk (fast, no VDF)
// - After betting closes, anyone can solve the VDF once to recover sk
// - sk enables batch decryption of all bets
//
// This leverages Wesolowski VDF's asymmetric verification property:
// one expensive evaluation, many cheap encryptions.
//
// NOTE: This implementation enforces a race-level delay for honest parties and
// enables "one expensive evaluation, many cheap verifications." It does NOT
// prevent a malicious race organizer from precomputing the VDF output and
// caching the race secret key; doing so would require integrating a VDE/MPC
// flow as outlined in the advisory.
class RaceLevelTimeLock {
public:
    // Create a new race-level timelock with specified VDF difficulty
    explicit RaceLevelTimeLock(std::uint64_t vdfIterations);

    // Initialize the timelock: generate keypair and encrypt secret key with VDF
    // contextLabel: unique identifier for this race (e.g., "race-123:mainnet:seed-xyz")
    void initialize(const std::string& contextLabel);

    // Get public key for bet encryption (hex-encoded, 32 bytes)
    std::string getPublicKeyHex() const;

    // Get VDF puzzle parameters (for transparency and verification)
    std::string getPuzzlePreimage() const;
    std::string getEncryptedSecretKeyHex() const;
    std::string getEncryptedSecretNonceHex() const;

    // Export full parameters for serialization
    RaceLevelTimeLockParams exportParams() const;

    // Import parameters (e.g., for verification or remote decryption)
    void importParams(const RaceLevelTimeLockParams& params);

    // Solve the VDF and unlock the secret key (expensive operation)
    // Returns true on success, false if already unlocked or VDF verification fails
    bool unlockSecretKey();

    // Check if secret key has been unlocked
    bool isUnlocked() const;

    // Encrypt plaintext using the public key (fast, no VDF required)
    // Uses crypto_box_seal for anonymous public-key encryption
    // Returns hex-encoded ciphertext
    std::string encrypt(const std::string& plaintext) const;

    // Decrypt ciphertext using the unlocked secret key
    // Returns nullopt if key not unlocked or decryption fails
    // ciphertextHex: hex-encoded output from encrypt()
    std::optional<std::string> decrypt(const std::string& ciphertextHex) const;

private:
    std::uint64_t vdfIterations_;
    std::string contextLabel_;
    std::string puzzlePreimage_;

    // Keypair (pk always available, sk only after VDF solve)
    std::vector<unsigned char> publicKey_;   // 32 bytes
    std::vector<unsigned char> secretKey_;   // 32 bytes (empty until unlocked)

    // Encrypted secret key storage
    std::vector<unsigned char> encryptedSecretKey_;
    std::vector<unsigned char> encryptedSecretNonce_;

    std::string vdfOutputHex_;
    std::string vdfProofHex_;

    bool initialized_ = false;
    bool unlocked_ = false;

    // Helper functions
    std::vector<unsigned char> hexToBytes(const std::string& hex) const;
    std::string bytesToHex(const unsigned char* data, std::size_t len) const;
    std::string deriveKeyFromVdf(const std::string& vdfOutput) const;
    bool decryptSecretKeyWithVdf(const std::string& vdfOutput);
};

} // namespace it
