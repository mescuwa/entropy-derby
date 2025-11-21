#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include "horse.hpp"
#include "transcript_log.hpp"

namespace it {

struct RaceConfig {
    std::vector<Horse> horses;
    double houseMargin;

    RaceConfig(std::vector<Horse> horses_, double houseMargin_)
        : horses(std::move(horses_)), houseMargin(houseMargin_) {}
};

struct RaceOutcome {
    std::uint32_t winningHorseId;
    std::vector<double> probabilities;

    RaceOutcome(std::uint32_t id, std::vector<double> probs)
        : winningHorseId(id), probabilities(std::move(probs)) {}
};

std::vector<double> computeProbabilities(const RaceConfig& cfg);

class RandomSource;
RaceOutcome runRace(const RaceConfig& cfg, RandomSource& rng);

struct RaceSimulationConfig {
    double trackLength = 100.0;
    double tickSeconds = 0.2;
    double baseSpeedScale = 40.0;
    double noiseScale = 8.0;
    std::size_t maxTicks = 1000;

    struct HorseDynamics {
        double speedMultiplier = 1.0;
        double acceleration = 0.0;
        double staminaThreshold = 1.0;
        double meanReversion = 1.5;
        double volatility = 1.0;
        double fatigueRate = 0.05;
        double recoveryRate = 0.02;
        double mudPreference = 0.5;
        double lateKick = 0.1;
    };

    struct InteractionConfig {
        double draftingDistance = 1.5;
        double draftingBoost = 0.05;
        double blockingDistance = 1.0;
        double blockingPenalty = 0.08;
        double chaosCoupling = 0.01; // sensitive to tiny perturbations.
    };

    InteractionConfig interaction{};

    bool enableDynamics = true;
    bool enableChaos = true;
    double mudLevel = 0.0;
    HorseDynamics defaultDynamics{};
    std::map<std::uint32_t, HorseDynamics> horseDynamics;
};

using RaceTickCallback =
    std::function<void(const std::vector<double>& positions, std::size_t tickIndex)>;

struct RaceTickState {
    std::size_t tick;
    // Microunits to maintain determinism; doubles preserved for API compatibility.
    std::vector<std::int64_t> positionsMicros;
    std::vector<double> positions;
    std::vector<double> speeds;
};

struct RaceSimulationResult {
    RaceOutcome outcome;
    std::vector<RaceTickState> transcript;
    TranscriptLog signedStates;
};

RaceSimulationResult runRaceSimulated(const RaceConfig& cfg,
                                      RandomSource& rng,
                                      const RaceSimulationConfig& simCfg,
                                      RaceTickCallback onTick);

} // namespace it
