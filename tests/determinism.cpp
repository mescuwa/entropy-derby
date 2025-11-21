#include "race.hpp"
#include "rng.hpp"

#include <array>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>

int main() {
    using namespace it;

    std::vector<Horse> horses;
    horses.emplace_back(0, "Red Comet", 1.0);
    horses.emplace_back(1, "Midnight Run", 2.0);
    horses.emplace_back(2, "Dust Devil", 3.0);
    horses.emplace_back(3, "Lucky Star", 4.0);

    RaceConfig cfg(std::move(horses), 0.10);

    // Deterministic VRF keypair derived from a fixed seed.
    const std::string seedHex =
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
    auto keys = deriveVrfKeypairFromSeed(seedHex);
    const std::string clientSeed = "determinism-client";
    const std::string deploymentId = "determinism-suite";
    const std::string chainId = "test-chain";

    RaceSimulationConfig simCfg;
    simCfg.maxTicks = 240;

    ProvablyFairRng rngA(
        keys.secretKeyHex, keys.publicKeyHex, clientSeed, 7, deploymentId, chainId);
    auto resultA = runRaceSimulated(cfg, rngA, simCfg, nullptr);

    ProvablyFairRng rngB(
        keys.secretKeyHex, keys.publicKeyHex, clientSeed, 7, deploymentId, chainId);
    auto resultB = runRaceSimulated(cfg, rngB, simCfg, nullptr);

    const auto& finishA = resultA.transcript.back();
    const auto& finishB = resultB.transcript.back();
    if (finishA.positions.size() != finishB.positions.size()) {
        std::cerr << "Transcript length mismatch\n";
        return 1;
    }

    for (std::size_t i = 0; i < finishA.positions.size(); ++i) {
        double delta = std::abs(finishA.positions[i] - finishB.positions[i]);
        if (delta > 1e-9) {
            std::cerr << "Determinism regression at horse " << i << "\n";
            return 1;
        }
    }

    if (resultA.outcome.winningHorseId != resultB.outcome.winningHorseId) {
        std::cerr << "Winning horse diverged across identical runs\n";
        return 1;
    }

    if (!ProvablyFairRng::verify(rngA.getVrfProof(),
                                 rngA.getVrfOutput(),
                                 rngA.getPublicKey(),
                                 rngA.getAlpha())) {
        std::cerr << "VRF verification failed\n";
        return 1;
    }

    if (resultA.signedStates.merkleRoot().empty()) {
        std::cerr << "Transcript Merkle root missing\n";
        return 1;
    }

    std::cout << "Determinism check passed. Merkle root: " << resultA.signedStates.merkleRoot()
              << "\n";
    return 0;
}
