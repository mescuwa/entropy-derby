#pragma once

#include <cstdint>

#include "fixed_point.hpp"

#include "race.hpp"

namespace it {

struct Bet {
    std::uint32_t horseId;
    std::uint64_t stake;
};

struct PayoutResult {
    std::int64_t netChange;
    Fixed64 impliedOdds;
};

PayoutResult resolveBet(const Bet& bet, const RaceOutcome& outcome, const RaceConfig& cfg);

} // namespace it

