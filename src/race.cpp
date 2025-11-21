#include "race.hpp"

#include "deterministic_math.hpp"
#include "fixed_point.hpp"
#include "rng.hpp"

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace it {

namespace {

double gaussianSample(RandomSource& rng) {
    return DeterministicMath::gaussianSample(rng);
}

Fixed64 clampFixed(Fixed64 value, Fixed64 minValue, Fixed64 maxValue) {
    if (value < minValue) {
        return minValue;
    }
    if (value > maxValue) {
        return maxValue;
    }
    return value;
}

Fixed64 absFixed(Fixed64 value) {
    static const Fixed64 zero = Fixed64::fromRaw(0);
    if (value >= zero) {
        return value;
    }
    return zero - value;
}

struct FixedHorseDynamics {
    Fixed64 speedMultiplier;
    Fixed64 acceleration;
    Fixed64 staminaThreshold;
    Fixed64 meanReversion;
    Fixed64 volatility;
    Fixed64 fatigueRate;
    Fixed64 recoveryRate;
    Fixed64 mudPreference;
    Fixed64 lateKick;
};

FixedHorseDynamics makeFixedDynamics(const RaceSimulationConfig::HorseDynamics& dyn) {
    return FixedHorseDynamics{
        Fixed64::fromDouble(dyn.speedMultiplier),
        Fixed64::fromDouble(dyn.acceleration),
        Fixed64::fromDouble(dyn.staminaThreshold),
        Fixed64::fromDouble(dyn.meanReversion),
        Fixed64::fromDouble(dyn.volatility),
        Fixed64::fromDouble(dyn.fatigueRate),
        Fixed64::fromDouble(dyn.recoveryRate),
        Fixed64::fromDouble(dyn.mudPreference),
        Fixed64::fromDouble(dyn.lateKick),
    };
}

struct FixedInteractionConfig {
    Fixed64 draftingDistance;
    Fixed64 draftingBoost;
    Fixed64 blockingDistance;
    Fixed64 blockingPenalty;
    Fixed64 chaosCoupling;
};

FixedInteractionConfig makeFixedInteraction(const RaceSimulationConfig::InteractionConfig& inter) {
    return FixedInteractionConfig{
        Fixed64::fromDouble(inter.draftingDistance),
        Fixed64::fromDouble(inter.draftingBoost),
        Fixed64::fromDouble(inter.blockingDistance),
        Fixed64::fromDouble(inter.blockingPenalty),
        Fixed64::fromDouble(inter.chaosCoupling),
    };
}

Fixed64 gaussianSampleFixed(RandomSource& rng) {
    return Fixed64::fromDouble(gaussianSample(rng));
}

Fixed64 uniformSampleFixed(RandomSource& rng) {
    return Fixed64::fromDouble(rng.uniform01());
}

Fixed64 centeredChaosComponent(std::uint64_t word) {
    constexpr std::uint64_t mask = (1ULL << 24) - 1ULL;
    std::uint64_t sample = word & mask;
    __int128 scaled = static_cast<__int128>(sample) * static_cast<__int128>(Fixed64::kScale);
    std::int64_t raw = static_cast<std::int64_t>(scaled / static_cast<__int128>(mask));
    Fixed64 fraction = Fixed64::fromRaw(raw);
    static const Fixed64 half = Fixed64::fromDouble(0.5);
    return fraction - half;
}

} // namespace

std::vector<double> computeProbabilities(const RaceConfig& cfg) {
    if (cfg.horses.empty()) {
        throw std::runtime_error("RaceConfig must have at least one horse");
    }

    double totalWeight = 0.0;
    for (const auto& h : cfg.horses) {
        if (h.weight <= 0.0) {
            throw std::runtime_error("Horse weight must be positive");
        }
        totalWeight += h.weight;
    }

    std::vector<double> probs;
    probs.reserve(cfg.horses.size());
    for (const auto& h : cfg.horses) {
        probs.push_back(h.weight / totalWeight);
    }

    return probs;
}

RaceOutcome runRace(const RaceConfig& cfg, RandomSource& rng) {
    auto probs = computeProbabilities(cfg);
    double r = rng.uniform01();

    double cumulative = 0.0;
    for (std::size_t i = 0; i < probs.size(); ++i) {
        cumulative += probs[i];
        if (r < cumulative) {
            return RaceOutcome(cfg.horses[i].id, std::move(probs));
        }
    }

    return RaceOutcome(cfg.horses.back().id, std::move(probs));
}

RaceSimulationResult runRaceSimulated(const RaceConfig& cfg,
                                      RandomSource& rng,
                                      const RaceSimulationConfig& simCfg,
                                      RaceTickCallback onTick) {
    auto probs = computeProbabilities(cfg);

    const std::size_t n = cfg.horses.size();
    if (n == 0) {
        throw std::runtime_error("RaceConfig must have at least one horse");
    }

    struct State {
        Fixed64 position{};
        Fixed64 speed{};
        Fixed64 fatigue{};
        bool lateKickApplied = false;
    };

    std::vector<State> states(n);
    std::size_t winnerIdx = 0;
    bool finished = false;

    std::vector<double> positions(n);
    std::vector<std::int64_t> positionsMicros(n);

    RaceSimulationResult result{ RaceOutcome(cfg.horses.front().id, probs), {}, {} };
    result.transcript.reserve(simCfg.maxTicks);

    const Fixed64 zero = Fixed64::fromRaw(0);
    const Fixed64 one = Fixed64::fromDouble(1.0);
    const Fixed64 half = Fixed64::fromDouble(0.5);
    const Fixed64 two = Fixed64::fromDouble(2.0);
    const Fixed64 fatigueClamp = Fixed64::fromDouble(0.9);
    const Fixed64 mudMin = Fixed64::fromDouble(0.2);
    const Fixed64 mudMax = Fixed64::fromDouble(1.2);

    const Fixed64 baseSpeedScale = Fixed64::fromDouble(simCfg.baseSpeedScale);
    const Fixed64 dt = Fixed64::fromDouble(simCfg.tickSeconds);
    const Fixed64 sqrtDt = Fixed64::fromDouble(DeterministicMath::sqrt(simCfg.tickSeconds));
    const Fixed64 trackLength = Fixed64::fromDouble(simCfg.trackLength);
    const Fixed64 lateKickThreshold = trackLength * Fixed64::fromDouble(0.8);
    const Fixed64 mudLevel = Fixed64::fromDouble(simCfg.mudLevel);
    const Fixed64 noiseScale = Fixed64::fromDouble(simCfg.noiseScale);

    std::vector<Fixed64> baseSpeeds(n);
    for (std::size_t i = 0; i < n; ++i) {
        Fixed64 probability = Fixed64::fromDouble(probs[i]);
        baseSpeeds[i] = baseSpeedScale * probability;
        states[i].speed = baseSpeeds[i];
    }

    auto dynamicsFor = [&](std::uint32_t horseId) -> const RaceSimulationConfig::HorseDynamics& {
        auto it = simCfg.horseDynamics.find(horseId);
        if (it != simCfg.horseDynamics.end()) {
            return it->second;
        }
        return simCfg.defaultDynamics;
    };

    std::vector<FixedHorseDynamics> horseDynamicsFixed(n);
    for (std::size_t i = 0; i < n; ++i) {
        horseDynamicsFixed[i] = makeFixedDynamics(dynamicsFor(cfg.horses[i].id));
    }

    FixedInteractionConfig interactionFixed = makeFixedInteraction(simCfg.interaction);

    auto appendCheckpoint = [&](std::size_t tick) {
        RaceTickState tickState;
        tickState.tick = tick;
        tickState.positionsMicros = positionsMicros;
        tickState.positions = positions;
        tickState.speeds.resize(n);
        for (std::size_t i = 0; i < n; ++i) {
            tickState.speeds[i] = states[i].speed.toDouble();
        }
        result.transcript.push_back(std::move(tickState));

        if ((tick + 1) % 100 == 0) {
            std::ostringstream oss;
            oss.setf(std::ios::fixed, std::ios::floatfield);
            oss << std::setprecision(12);
            oss << "tick=" << tick << ";";
            for (std::size_t i = 0; i < n; ++i) {
                oss << positions[i] << "/" << states[i].speed.toDouble();
                if (i + 1 < n) {
                    oss << "|";
                }
            }
            result.signedStates.append(oss.str());
        }
    };

    auto interactionNudge = [&](std::size_t idx) -> Fixed64 {
        if (!simCfg.enableChaos || n <= 1) {
            return zero;
        }
        const auto& inter = interactionFixed;
        Fixed64 deltaBoost = zero;
        Fixed64 deltaPenalty = zero;
        const Fixed64 position = states[idx].position;
        for (std::size_t j = 0; j < n; ++j) {
            if (j == idx) {
                continue;
            }
            Fixed64 gap = states[j].position - position;
            if (gap > zero && inter.draftingDistance > zero && gap < inter.draftingDistance) {
                Fixed64 closeness = one - (gap / inter.draftingDistance);
                closeness = clampFixed(closeness, zero, one);
                Fixed64 boost = inter.draftingBoost * closeness;
                boost *= states[j].speed;
                deltaBoost += boost;
            } else if (gap < zero && inter.blockingDistance > zero &&
                       absFixed(gap) < inter.blockingDistance) {
                Fixed64 absGap = absFixed(gap);
                Fixed64 closeness = one - (absGap / inter.blockingDistance);
                closeness = clampFixed(closeness, zero, one);
                Fixed64 penalty = inter.blockingPenalty * closeness;
                penalty *= absFixed(states[idx].speed);
                deltaPenalty += penalty;
            }

            std::uint64_t chaosWord =
                static_cast<std::uint64_t>(position.raw() ^ states[j].position.raw());
            Fixed64 chaosComponent = centeredChaosComponent(chaosWord);
            deltaBoost += chaosComponent * inter.chaosCoupling;
        }
        return deltaBoost - deltaPenalty;
    };

    for (std::size_t tick = 0; tick < simCfg.maxTicks && !finished; ++tick) {
        for (std::size_t i = 0; i < n; ++i) {
            Fixed64 baseSpeed = baseSpeeds[i];

            if (simCfg.enableDynamics) {
                const auto& dyn = horseDynamicsFixed[i];
                Fixed64 mudModifier = one - mudLevel * (one - dyn.mudPreference);
                mudModifier = clampFixed(mudModifier, mudMin, mudMax);

                Fixed64 targetSpeed = baseSpeed * dyn.speedMultiplier;
                targetSpeed *= mudModifier;

                Fixed64 fatigueValue = states[i].fatigue;
                if (fatigueValue > fatigueClamp) {
                    fatigueValue = fatigueClamp;
                }
                Fixed64 fatiguePenalty = one - fatigueValue;
                targetSpeed *= fatiguePenalty;

                Fixed64 drift = dyn.meanReversion * (targetSpeed - states[i].speed);
                drift *= dt;

                Fixed64 stochastic = dyn.volatility * sqrtDt;
                stochastic *= gaussianSampleFixed(rng);

                Fixed64 accel = dyn.acceleration * dt;
                states[i].speed += drift + stochastic + accel;

                if (simCfg.enableChaos) {
                    states[i].speed += interactionNudge(i);
                }

                if (!states[i].lateKickApplied && states[i].position >= lateKickThreshold) {
                    states[i].speed += targetSpeed * dyn.lateKick;
                    states[i].lateKickApplied = true;
                }
                if (states[i].speed < zero) {
                    states[i].speed = zero;
                }

                Fixed64 delta = states[i].speed * dt;
                states[i].position += delta;

                Fixed64 stamina = dyn.staminaThreshold;
                if (states[i].speed > stamina) {
                    Fixed64 over = states[i].speed - stamina;
                    Fixed64 fatigueGain = over * dyn.fatigueRate;
                    fatigueGain *= dt;
                    states[i].fatigue += fatigueGain;
                    if (states[i].fatigue > one) {
                        states[i].fatigue = one;
                    }
                } else {
                    Fixed64 recovery = dyn.recoveryRate * dt;
                    states[i].fatigue -= recovery;
                    if (states[i].fatigue < zero) {
                        states[i].fatigue = zero;
                    }
                }
            } else {
                Fixed64 delta = baseSpeed * dt;
                if (noiseScale > zero) {
                    Fixed64 centered = (uniformSampleFixed(rng) - half) * two;
                    Fixed64 noise = centered * noiseScale;
                    delta = (baseSpeed + noise) * dt;
                }
                if (delta < zero) {
                    delta = zero;
                }
                states[i].position += delta;
            }
        }

        for (std::size_t i = 0; i < n; ++i) {
            positionsMicros[i] = states[i].position.raw();
            positions[i] = states[i].position.toDouble();
        }

        if (onTick) {
            onTick(positions, tick);
        }

        appendCheckpoint(tick);

        for (std::size_t i = 0; i < n; ++i) {
            if (states[i].position >= trackLength) {
                if (!finished || states[i].position > states[winnerIdx].position) {
                    finished = true;
                    winnerIdx = i;
                }
            }
        }
    }

    if (!result.transcript.empty()) {
        const auto& last = result.transcript.back();
        if ((last.tick + 1) % 100 != 0) {
            std::ostringstream oss;
            oss.setf(std::ios::fixed, std::ios::floatfield);
            oss << std::setprecision(12);
            oss << "tick=" << last.tick << ";";
            for (std::size_t i = 0; i < n; ++i) {
                oss << last.positions[i] << "/" << last.speeds[i];
                if (i + 1 < n) {
                    oss << "|";
                }
            }
            result.signedStates.append(oss.str());
        }
    }

    if (!finished) {
        Fixed64 bestPos = states[0].position;
        winnerIdx = 0;
        for (std::size_t i = 1; i < n; ++i) {
            if (states[i].position > bestPos) {
                bestPos = states[i].position;
                winnerIdx = i;
            }
        }
    }

    result.outcome = RaceOutcome(cfg.horses[winnerIdx].id, std::move(probs));
    return result;
}

} // namespace it
