#pragma once

#include "rng.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace it {

enum class ProtocolPhase {
    ACCEPTING_COMMITMENTS,
    COMMITMENT_LOCKED,
    ACCEPTING_REVEALS,
    FINALIZED,
    ABORTED
};

// Shared interface for any entropy coordinator that plugs into the race engine.
class EntropyProtocol : public RandomSource {
public:
    ~EntropyProtocol() override = default;

    virtual ProtocolPhase getPhase() const = 0;
    virtual bool lockCommitments() = 0;
    virtual bool finalizeEntropy() = 0;

    virtual std::string getFinalSeed() const = 0;
    virtual std::string getVdfProof() const = 0;
    virtual std::uint64_t getVdfIterations() const = 0;
    virtual std::string getFinalPreimage() const = 0;

    virtual double getParticipationRate() const = 0;
    virtual std::vector<std::string> getAbsentParticipants() const = 0;
};

} // namespace it

