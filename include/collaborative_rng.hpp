#pragma once

#include "entropy_protocol.hpp"
#include "rng.hpp"
#include "vdf.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace it {

// Phase 1: Commitment
struct SeedCommitment {
    std::string participantId;
    std::string commitment; // SHA-256 of canonicalized seed/salt (seed:<len>:<seed>;salt:<len>:<salt>;)
    std::uint64_t stake;
    std::uint64_t timestamp;
};

// Phase 2: Reveal
struct SeedReveal {
    std::string participantId;
    std::string seed;
    std::string salt;
};

class CollaborativeRng : public EntropyProtocol {
public:
    struct Config {
        std::uint64_t minStake = 100;
        std::uint32_t minParticipants = 3;
        std::uint32_t commitmentWindow = 60;
        std::uint32_t revealWindow = 30;
        double abortThreshold = 0.33;
        double abortPenaltyMultiplier = 2.0;
        std::uint64_t maxStakeWeight = 100;
        bool enableVdf = true;
        std::uint32_t vdfDifficulty = kDefaultWesolowskiIterations;
    };

    explicit CollaborativeRng(const Config& cfg, const std::string& serverSeed);

    bool addCommitment(const SeedCommitment& commitment);
    bool lockCommitments() override;

    bool addReveal(const SeedReveal& reveal);
    bool finalizeEntropy() override;

    double uniform01() override;

    ProtocolPhase getPhase() const override { return phase_; }
    std::vector<SeedCommitment> getCommitments() const { return commitments_; }
    std::vector<SeedReveal> getReveals() const { return reveals_; }
    std::string getFinalSeed() const override { return finalSeed_; }
    std::string getVdfProof() const override { return finalVdfProof_; }
    std::uint64_t getVdfIterations() const override { return vdfIterations_; }
    std::string getFinalPreimage() const override { return finalPreimage_; }

    bool verifyCommitment(const SeedReveal& reveal) const;
    bool verifyFinalSeed() const;
    double getParticipationRate() const override;
    std::vector<std::string> getAbsentParticipants() const override;

private:
    Config config_;
    std::string serverSeed_;
    ProtocolPhase phase_;

    std::vector<SeedCommitment> commitments_;
    std::map<std::string, SeedCommitment> commitmentMap_;

    std::vector<SeedReveal> reveals_;
    std::map<std::string, SeedReveal> revealMap_;

    std::string finalSeed_;
    std::uint64_t callCount_;
    std::string finalVdfProof_;
    std::uint64_t vdfIterations_;
    std::string finalPreimage_;

    std::string computeFinalSeed(std::string& proofOut,
                                 std::uint64_t& iterationsOut,
                                 std::string& preimageOut) const;
    bool validateReveal(const SeedReveal& reveal) const;
};

} // namespace it
