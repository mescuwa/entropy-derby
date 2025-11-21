#include "collaborative_rng.hpp"

#include "picosha2.h"
#include "vdf.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace it {

namespace {

bool isHexString(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

// Conservative throughput bound (~150k squarings/sec on commodity CPU) to keep VDF slower
// than the reveal window even on fast hardware.
constexpr std::uint32_t kVdfIterationsPerSecondFloor = 150'000;
// Hard floor to prevent trivially fast VDFs even with very short windows.
constexpr std::uint32_t kAbsoluteVdfSecurityFloor = 1'000'000;

std::uint32_t minimumVdfDifficulty(const CollaborativeRng::Config& cfg) {
    if (!cfg.enableVdf) {
        return 0;
    }
    std::uint64_t estimatedIterations =
        static_cast<std::uint64_t>(cfg.revealWindow) *
        static_cast<std::uint64_t>(kVdfIterationsPerSecondFloor);
    if (estimatedIterations > kMaxWesolowskiIterations) {
        throw std::invalid_argument(
            "Reveal window requires more VDF iterations than the built-in prover supports; "
            "reduce revealWindow or switch to a faster VDF backend.");
    }
    std::uint32_t required = static_cast<std::uint32_t>(estimatedIterations);
    required = std::max(required, kAbsoluteVdfSecurityFloor);
    required = std::max(required, kMinWesolowskiIterations);
    return required;
}

void appendLengthPrefixed(std::ostringstream& oss, const std::string& value) {
    oss << value.size() << ':';
    oss.write(value.data(), value.size());
    oss << ';';
}

std::string buildCommitmentPreimage(const SeedReveal& reveal) {
    std::ostringstream oss;
    oss << "seed:";
    appendLengthPrefixed(oss, reveal.seed);
    oss << "salt:";
    appendLengthPrefixed(oss, reveal.salt);
    return oss.str();
}

} // namespace

CollaborativeRng::CollaborativeRng(const Config& cfg, const std::string& serverSeed)
    : config_(cfg)
    , serverSeed_(serverSeed)
    , phase_(ProtocolPhase::ACCEPTING_COMMITMENTS)
    , finalSeed_()
    , callCount_(0)
    , finalVdfProof_()
    , vdfIterations_(0)
    , finalPreimage_() {
    if (config_.enableVdf) {
        std::uint32_t minDifficulty = minimumVdfDifficulty(config_);
        if (config_.vdfDifficulty < minDifficulty) {
            std::ostringstream oss;
            oss << "VDF difficulty (" << config_.vdfDifficulty << ") is below the minimum required ("
                << minDifficulty << ") for a " << config_.revealWindow
                << "s reveal window; increase vdfDifficulty or shorten revealWindow";
            throw std::invalid_argument(oss.str());
        }
        if (config_.vdfDifficulty > kMaxWesolowskiIterations) {
            std::ostringstream oss;
            oss << "VDF difficulty (" << config_.vdfDifficulty
                << ") exceeds supported maximum of " << kMaxWesolowskiIterations;
            throw std::invalid_argument(oss.str());
        }
    }
}

bool CollaborativeRng::addCommitment(const SeedCommitment& commitment) {
    if (phase_ != ProtocolPhase::ACCEPTING_COMMITMENTS) {
        return false;
    }
    if (commitment.stake < config_.minStake) {
        return false;
    }
    if (commitmentMap_.count(commitment.participantId) != 0) {
        return false;
    }

    commitments_.push_back(commitment);
    commitmentMap_.emplace(commitment.participantId, commitment);
    return true;
}

bool CollaborativeRng::lockCommitments() {
    if (phase_ != ProtocolPhase::ACCEPTING_COMMITMENTS) {
        return false;
    }

    if (commitments_.size() < config_.minParticipants) {
        phase_ = ProtocolPhase::ABORTED;
        return false;
    }

    phase_ = ProtocolPhase::COMMITMENT_LOCKED;
    return true;
}

bool CollaborativeRng::addReveal(const SeedReveal& reveal) {
    if (phase_ != ProtocolPhase::COMMITMENT_LOCKED && phase_ != ProtocolPhase::ACCEPTING_REVEALS) {
        return false;
    }
    if (phase_ == ProtocolPhase::COMMITMENT_LOCKED) {
        phase_ = ProtocolPhase::ACCEPTING_REVEALS;
    }
    if (commitmentMap_.count(reveal.participantId) == 0) {
        return false;
    }
    if (revealMap_.count(reveal.participantId) != 0) {
        return false;
    }
    if (!validateReveal(reveal)) {
        return false;
    }

    reveals_.push_back(reveal);
    revealMap_.emplace(reveal.participantId, reveal);
    return true;
}

bool CollaborativeRng::validateReveal(const SeedReveal& reveal) const {
    auto it = commitmentMap_.find(reveal.participantId);
    if (it == commitmentMap_.end()) {
        return false;
    }
    if ((reveal.seed.size() % 2) != 0 || (reveal.salt.size() % 2) != 0) {
        return false;
    }
    if (!isHexString(reveal.seed) || !isHexString(reveal.salt)) {
        return false;
    }
    std::string commitmentPreimage = buildCommitmentPreimage(reveal);
    std::string computedHash = ProvablyFairRng::hashSeed(commitmentPreimage);
    return computedHash == it->second.commitment;
}

bool CollaborativeRng::finalizeEntropy() {
    if (phase_ == ProtocolPhase::FINALIZED) {
        return true;
    }
    if (phase_ != ProtocolPhase::ACCEPTING_REVEALS) {
        return false;
    }

    double participationRate = getParticipationRate();
    if (participationRate < (1.0 - config_.abortThreshold)) {
        phase_ = ProtocolPhase::ABORTED;
        return false;
    }

    std::string proof;
    std::uint64_t iterations = 0;
    std::string preimage;
    finalSeed_ = computeFinalSeed(proof, iterations, preimage);
    finalVdfProof_ = std::move(proof);
    vdfIterations_ = iterations;
    finalPreimage_ = std::move(preimage);
    phase_ = ProtocolPhase::FINALIZED;
    callCount_ = 0;
    return true;
}

std::string CollaborativeRng::computeFinalSeed(std::string& proofOut,
                                               std::uint64_t& iterationsOut,
                                               std::string& preimageOut) const {
    std::vector<SeedReveal> sortedReveals = reveals_;
    std::sort(sortedReveals.begin(),
              sortedReveals.end(),
              [](const SeedReveal& a, const SeedReveal& b) { return a.participantId < b.participantId; });

    std::ostringstream oss;
    struct WeightedReveal {
        const SeedReveal* reveal;
        std::uint64_t weight;
    };
    std::vector<WeightedReveal> weighted;
    weighted.reserve(sortedReveals.size());
    std::uint64_t totalWeight = 0;
    for (const auto& reveal : sortedReveals) {
        auto commitIt = commitmentMap_.find(reveal.participantId);
        if (commitIt == commitmentMap_.end()) {
            continue;
        }
        std::uint64_t stake = commitIt->second.stake;
        if (stake == 0) {
            continue;
        }
        std::uint64_t weight = stake;
        weighted.push_back({ &reveal, weight });
        if (std::numeric_limits<std::uint64_t>::max() - totalWeight < weight) {
            totalWeight = std::numeric_limits<std::uint64_t>::max();
        } else {
            totalWeight += weight;
        }
    }

    std::uint64_t maxBudget = config_.maxStakeWeight;
    std::vector<std::uint64_t> scaledWeights;
    scaledWeights.reserve(weighted.size());

    if (maxBudget > 0 && totalWeight > maxBudget) {
        // Apportion the capped budget with a largest-remainder method so no ordering can censor
        // higher-stake participants; tie-breaking mixes in the hidden server seed to block
        // lexicographic Sybil IDs from monopolizing the leftover slots.
        struct RemainderInfo {
            std::size_t index;
            std::uint64_t remainder;
            std::uint64_t tieBreaker;
        };
        std::vector<RemainderInfo> remainderInfo;
        remainderInfo.reserve(weighted.size());

        std::uint64_t baseAssigned = 0;
        for (std::size_t i = 0; i < weighted.size(); ++i) {
            __int128 scaledNumerator =
                static_cast<__int128>(weighted[i].weight) * static_cast<__int128>(maxBudget);
            std::uint64_t baseWeight = static_cast<std::uint64_t>(scaledNumerator / totalWeight);
            std::uint64_t remainder = static_cast<std::uint64_t>(scaledNumerator % totalWeight);
            scaledWeights.push_back(baseWeight);
            baseAssigned += baseWeight;

            std::ostringstream tie;
            tie << weighted[i].reveal->participantId << '|' << weighted[i].reveal->seed << '|'
                << weighted[i].reveal->salt << '|' << serverSeed_;
            auto tieMaterial = tie.str();
            std::array<std::uint8_t, 32> hash{};
            picosha2::hash256(tieMaterial.begin(), tieMaterial.end(), hash.begin(), hash.end());
            std::uint64_t tieBreaker = 0;
            for (int b = 0; b < 8; ++b) {
                tieBreaker = (tieBreaker << 8) | hash[b];
            }

            remainderInfo.push_back({ i, remainder, tieBreaker });
        }

        std::uint64_t leftover = 0;
        if (maxBudget > baseAssigned) {
            leftover = maxBudget - baseAssigned;
        }

        std::sort(remainderInfo.begin(),
                  remainderInfo.end(),
                  [](const RemainderInfo& a, const RemainderInfo& b) {
                      if (a.remainder == b.remainder) {
                          return a.tieBreaker < b.tieBreaker;
                      }
                      return a.remainder > b.remainder;
                  });

        for (std::size_t i = 0; i < remainderInfo.size() && i < leftover; ++i) {
            scaledWeights[remainderInfo[i].index] += 1;
        }
    } else {
        for (const auto& entry : weighted) {
            scaledWeights.push_back(entry.weight);
        }
    }

    std::uint64_t appended = 0;
    for (std::size_t idx = 0; idx < weighted.size(); ++idx) {
        std::uint64_t scaledWeight = scaledWeights[idx];
        for (std::uint64_t i = 0; i < scaledWeight; ++i) {
            appendLengthPrefixed(oss, weighted[idx].reveal->seed);
        }
        if (maxBudget > 0) {
            appended += scaledWeight;
            if (appended >= maxBudget) {
                break;
            }
        }
    }
    appendLengthPrefixed(oss, serverSeed_);
    preimageOut = oss.str();

    if (!config_.enableVdf) {
        proofOut.clear();
        iterationsOut = 0;
        return ProvablyFairRng::hashSeed(preimageOut);
    }

    WesolowskiVdf vdf(config_.vdfDifficulty);
    VdfResult result = vdf.evaluate(preimageOut);
    proofOut = result.proofHex;
    iterationsOut = result.iterations;
    return result.outputHex;
}

double CollaborativeRng::uniform01() {
    if (phase_ != ProtocolPhase::FINALIZED) {
        throw std::runtime_error("CollaborativeRng not finalized");
    }

    std::ostringstream oss;
    oss << finalSeed_ << ":" << callCount_;
    std::string input = oss.str();
    ++callCount_;

    std::array<std::uint8_t, 32> hash{};
    picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());

    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | hash[i];
    }
    const std::uint64_t mask = (1ULL << 53) - 1;
    val &= mask;
    return static_cast<double>(val) / static_cast<double>(1ULL << 53);
}

double CollaborativeRng::getParticipationRate() const {
    if (commitments_.empty()) {
        return 0.0;
    }
    return static_cast<double>(reveals_.size()) / static_cast<double>(commitments_.size());
}

std::vector<std::string> CollaborativeRng::getAbsentParticipants() const {
    std::vector<std::string> absent;
    for (const auto& commitment : commitments_) {
        if (revealMap_.count(commitment.participantId) == 0) {
            absent.push_back(commitment.participantId);
        }
    }
    return absent;
}

bool CollaborativeRng::verifyCommitment(const SeedReveal& reveal) const {
    return validateReveal(reveal);
}

bool CollaborativeRng::verifyFinalSeed() const {
    if (phase_ != ProtocolPhase::FINALIZED) {
        return false;
    }
    if (!config_.enableVdf) {
        return true;
    }
    WesolowskiVdf vdf(config_.vdfDifficulty);
    VdfResult r{ finalSeed_, finalVdfProof_, vdfIterations_ };
    return vdf.verify(finalPreimage_, r);
}

} // namespace it
