#include "race.hpp"
#include "rng.hpp"

#include <iostream>
#include <vector>

namespace {

it::RaceConfig defaultConfig() {
    std::vector<it::Horse> horses;
    horses.emplace_back(0, "Red Comet", 1.0);
    horses.emplace_back(1, "Midnight Run", 2.0);
    horses.emplace_back(2, "Dust Devil", 3.0);
    horses.emplace_back(3, "Lucky Star", 4.0);
    horses.emplace_back(4, "Iron Hoof", 5.0);
    horses.emplace_back(5, "Wild Wind", 6.0);
    return it::RaceConfig(std::move(horses), 0.10);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 7) {
        std::cerr
            << "Usage: audit_race <vrfOutputHex> <vrfProofHex> <publicKeyHex> <clientSeed> <nonce> <deploymentId> [chainId]\n";
        return 1;
    }

    std::string vrfOutput = argv[1];
    std::string vrfProof = argv[2];
    std::string publicKey = argv[3];
    std::string clientSeed = argv[4];
    std::string deploymentId = argv[6];
    std::string chainId = (argc > 7) ? argv[7] : "";
    std::uint64_t nonce = 0;
    try {
        nonce = std::stoull(argv[5]);
    } catch (const std::exception& ex) {
        std::cerr << "Nonce must be an unsigned integer: " << ex.what() << '\n';
        return 1;
    }

    it::RaceConfig cfg = defaultConfig();
    it::ProvablyFairRng rng(vrfOutput, vrfProof, publicKey, clientSeed, nonce, deploymentId, chainId);
    auto outcome = it::runRace(cfg, rng);

    bool ok = it::ProvablyFairRng::verify(vrfProof, vrfOutput, publicKey, rng.getAlpha());
    std::cout << "VRF verification: " << (ok ? "valid" : "INVALID") << '\n';
    std::cout << "Winner: " << outcome.winningHorseId << '\n';
    for (std::size_t i = 0; i < outcome.probabilities.size(); ++i) {
        std::cout << "  Horse " << cfg.horses[i].name << " (ID " << cfg.horses[i].id
                  << ") p ~= " << outcome.probabilities[i] << '\n';
    }

    return 0;
}
