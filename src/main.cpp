#include "betting.hpp"
#include "horse.hpp"
#include "race.hpp"
#include "rng.hpp"

#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

using namespace it;

namespace {

void printHorsesWithProbabilities(const RaceConfig& cfg, const std::vector<double>& probs) {
    std::cout << "Horses and implied fair probabilities:\n";
    for (std::size_t i = 0; i < cfg.horses.size(); ++i) {
        std::cout << "  [" << cfg.horses[i].id << "] " << cfg.horses[i].name << "  p ~= " << probs[i] << "\n";
    }
}

void printRaceTick(const RaceConfig& cfg,
                   const RaceSimulationConfig& simCfg,
                   const std::vector<double>& positions,
                   std::size_t tickIndex) {
    const int trackWidth = 40;
    std::cout << "\nTick " << tickIndex << "\n";
    for (std::size_t i = 0; i < cfg.horses.size(); ++i) {
        double frac = positions[i] / simCfg.trackLength;
        if (frac < 0.0) {
            frac = 0.0;
        }
        if (frac > 1.0) {
            frac = 1.0;
        }
        int marker = static_cast<int>(frac * trackWidth);
        if (marker < 0) {
            marker = 0;
        }
        if (marker >= trackWidth) {
            marker = trackWidth - 1;
        }

        std::cout << "[" << cfg.horses[i].id << "] " << cfg.horses[i].name << "  |";
        for (int x = 0; x < trackWidth; ++x) {
            if (x == marker) {
                std::cout << ">";
            } else {
                std::cout << "-";
            }
        }
        std::cout << "|\n";
    }
}

} // namespace

int main() {
    std::vector<Horse> horses;
    horses.emplace_back(0, "Red Comet", 1.0);
    horses.emplace_back(1, "Midnight Run", 2.0);
    horses.emplace_back(2, "Dust Devil", 3.0);
    horses.emplace_back(3, "Lucky Star", 4.0);
    horses.emplace_back(4, "Iron Hoof", 5.0);
    horses.emplace_back(5, "Wild Wind", 6.0);

    RaceConfig cfg(std::move(horses), 0.10);
    std::int64_t bankroll = 1000;
    std::uint64_t raceCounter = 0;
    VrfKeyPair houseKeys = generateVrfKeypair();

    std::cout << "Welcome to Entropy Derby: Inside-Track-But-Better.\n";
    std::cout << "House VRF public key (commitment): " << houseKeys.publicKeyHex << "\n";
    const char* deploymentEnv = std::getenv("IT_DEPLOYMENT_ID");
    const char* chainEnv = std::getenv("IT_CHAIN_ID");
    std::string deploymentId = deploymentEnv ? deploymentEnv : "local-cli";
    std::string chainId = chainEnv ? chainEnv : "offchain";
    std::cout << "Using deploymentId=" << deploymentId;
    if (!chainId.empty()) {
        std::cout << " chainId=" << chainId;
    }
    std::cout << " (set IT_DEPLOYMENT_ID/IT_CHAIN_ID to override)\n";
    bool running = true;

    while (running) {
        if (bankroll <= 0) {
            std::cout << "\nYou are out of funds. Session over.\n";
            break;
        }

        auto probs = computeProbabilities(cfg);
        std::cout << "\n----------------------------------------\n";
        std::cout << "Current bankroll: " << bankroll << "\n";
        printHorsesWithProbabilities(cfg, probs);

        std::cout << "\nEnter horse id to bet on (or -1 to quit): ";
        int horseChoice;
        if (!(std::cin >> horseChoice)) {
            return 0;
        }

        if (horseChoice < 0) {
            std::cout << "Exiting.\n";
            break;
        }

        bool validHorse = false;
        for (const auto& h : cfg.horses) {
            if (static_cast<int>(h.id) == horseChoice) {
                validHorse = true;
                break;
            }
        }

        if (!validHorse) {
            std::cout << "Unknown horse id. Try again.\n";
            continue;
        }

        std::cout << "Stake amount (max " << bankroll << "): ";
        std::uint64_t stake;
        if (!(std::cin >> stake)) {
            return 0;
        }

        if (stake == 0 || stake > static_cast<std::uint64_t>(bankroll)) {
            std::cout << "Invalid stake. Try again.\n";
            continue;
        }

        std::cout << "Race mode: [1] Instant, [2] Simulated: ";
        int mode = 1;
        if (!(std::cin >> mode)) {
            return 0;
        }

        std::cout << "\n=== VERIFIABLE RANDOMNESS SETUP ===\n";
        std::cout << "Server VRF commitment (public key): " << houseKeys.publicKeyHex << "\n";
        std::cout << "Enter your client seed (blank = random): ";
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string clientSeed;
        std::getline(std::cin, clientSeed);
        if (clientSeed.empty()) {
            clientSeed = generateServerSeed().substr(0, 16);
            std::cout << "Generated client seed: " << clientSeed << "\n";
        }

        std::uint64_t nonce = raceCounter++;
        ProvablyFairRng provRng(houseKeys.secretKeyHex,
                                houseKeys.publicKeyHex,
                                clientSeed,
                                nonce,
                                deploymentId,
                                chainId);

        Bet bet{ static_cast<std::uint32_t>(horseChoice), stake };

        RaceOutcome outcome{ 0, {} };
        if (mode == 2) {
            RaceSimulationConfig simCfg;
            std::cout << "\nStarting simulated race...\n";
            auto simResult =
                runRaceSimulated(cfg, provRng, simCfg, [&](const std::vector<double>& positions, std::size_t tick) {
                    printRaceTick(cfg, simCfg, positions, tick);
                    std::this_thread::sleep_for(std::chrono::milliseconds(120));
                });
            outcome = simResult.outcome;
            std::cout << "\nTranscript Merkle root (every 100 ticks): "
                      << simResult.signedStates.merkleRoot() << "\n";
        } else {
            outcome = runRace(cfg, provRng);
        }

        auto result = resolveBet(bet, outcome, cfg);

        std::cout << "\nRace finished!\n";
        std::cout << "Winning horse: " << outcome.winningHorseId << "\n";

        bankroll += result.netChange;
        if (outcome.winningHorseId == bet.horseId) {
            std::cout << "You won. Net change: " << result.netChange << "  New bankroll: " << bankroll << "\n";
        } else {
            std::cout << "You lost. Net change: " << result.netChange << "  New bankroll: " << bankroll << "\n";
        }

        std::cout << "\n=== PROVABLY FAIR REVEAL ===\n";
        std::cout << "VRF public key: " << provRng.getPublicKey() << "\n";
        std::cout << "VRF input (alpha): " << provRng.getAlpha() << "\n";
        std::cout << "VRF proof: " << provRng.getVrfProof() << "\n";
        std::cout << "VRF output: " << provRng.getVrfOutput() << "\n";
        std::cout << "Client seed: " << provRng.getClientSeed() << "\n";
        std::cout << "Nonce: " << provRng.getNonce() << "\n";
        std::cout << "Deployment scope: " << provRng.getDeploymentId();
        if (!provRng.getChainId().empty()) {
            std::cout << " | " << provRng.getChainId();
        }
        std::cout << "\n";
        std::cout << "Calls consumed: " << provRng.getCallCount() << "\n";
        bool ok = ProvablyFairRng::verify(provRng.getVrfProof(),
                                          provRng.getVrfOutput(),
                                          provRng.getPublicKey(),
                                          provRng.getAlpha());
        std::cout << "VRF verification: " << (ok ? "valid" : "INVALID") << "\n";
        std::cout << "Share tuple pk, proof, output, alpha, client seed, nonce, deploymentId, chainId to let others verify.\n";
    }

    std::cout << "\nFinal bankroll: " << bankroll << "\n";
    std::cout << "Thanks for playing.\n";
    return 0;
}
