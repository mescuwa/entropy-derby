#include "betting.hpp"

#include "fixed_point.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace it {

namespace {

std::int64_t checkedStakeToInt64(std::uint64_t stake) {
    constexpr std::uint64_t maxStake =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (stake > maxStake) {
        throw std::runtime_error("stake too large for Fixed64");
    }
    return static_cast<std::int64_t>(stake);
}

} // namespace

PayoutResult resolveBet(const Bet& bet, const RaceOutcome& outcome, const RaceConfig& cfg) {
    if (outcome.probabilities.size() != cfg.horses.size()) {
        throw std::runtime_error("Outcome probabilities do not match horses");
    }

    std::size_t chosenIdx = cfg.horses.size();
    std::size_t winnerIdx = cfg.horses.size();

    for (std::size_t i = 0; i < cfg.horses.size(); ++i) {
        if (cfg.horses[i].id == bet.horseId) {
            chosenIdx = i;
        }
        if (cfg.horses[i].id == outcome.winningHorseId) {
            winnerIdx = i;
        }
    }

    if (chosenIdx == cfg.horses.size()) {
        throw std::runtime_error("Bet references unknown horse");
    }
    if (winnerIdx == cfg.horses.size()) {
        throw std::runtime_error("Outcome references unknown horse");
    }

    double probabilityScalar = outcome.probabilities[chosenIdx];
    if (probabilityScalar <= 0.0) {
        throw std::runtime_error("Chosen horse has zero probability");
    }

    Fixed64 probability = Fixed64::fromDouble(probabilityScalar);
    if (probability.raw() <= 0) {
        throw std::runtime_error("Probability underflow after fixed-point conversion");
    }

    Fixed64 one = Fixed64::fromDouble(1.0);
    Fixed64 rawOdds = one / probability;

    double marginScalar = std::clamp(cfg.houseMargin, 0.0, 0.99);
    Fixed64 houseFactor = one - Fixed64::fromDouble(marginScalar);
    Fixed64 effectiveOdds = rawOdds * houseFactor;

    if (chosenIdx != winnerIdx) {
        return PayoutResult{ -checkedStakeToInt64(bet.stake), effectiveOdds };
    }

    __int128 scaled = static_cast<__int128>(bet.stake) * static_cast<__int128>(effectiveOdds.raw());
    if (scaled < 0) {
        scaled = 0;
    }
    __int128 payout128 = scaled / Fixed64::kScale;
    if (payout128 < 0) {
        payout128 = 0;
    }
    constexpr __int128 maxUint64 = static_cast<__int128>(std::numeric_limits<std::uint64_t>::max());
    if (payout128 > maxUint64) {
        throw std::runtime_error("grossPayout overflow: bad stake/odds config");
    }
    std::uint64_t grossPayout = static_cast<std::uint64_t>(payout128);
    constexpr __int128 maxInt64 = static_cast<__int128>(std::numeric_limits<std::int64_t>::max());
    if (payout128 > maxInt64) {
        throw std::runtime_error("grossPayout exceeds signed range");
    }
    std::int64_t net = static_cast<std::int64_t>(grossPayout) - checkedStakeToInt64(bet.stake);
    return PayoutResult{ net, effectiveOdds };
}

} // namespace it

