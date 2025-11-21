#include "betting.hpp"
#include "race.hpp"
#include "rng.hpp"

#include <algorithm>
#include <iomanip>
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

int main() {
    auto cfg = defaultConfig();
    auto probs = it::computeProbabilities(cfg);

    std::cout << "=== HOUSE EDGE ANALYSIS ===\n";
    std::cout << "Configured margin: " << (cfg.houseMargin * 100.0) << "%\n\n";

    std::cout << "Expected value per $100 bet:\n";
    for (std::size_t i = 0; i < cfg.horses.size(); ++i) {
        double fairOdds = 1.0 / probs[i];
        double effectiveOdds = fairOdds * (1.0 - cfg.houseMargin);
        double ev = (effectiveOdds * probs[i] - 1.0) * 100.0;
        std::cout << "  " << std::setw(12) << std::left << cfg.horses[i].name << " : "
                  << std::fixed << std::setprecision(2) << ev << '\n';
    }

    auto minProbIter = std::min_element(probs.begin(), probs.end());
    auto maxProbIter = std::max_element(probs.begin(), probs.end());
    std::size_t underdogIdx = static_cast<std::size_t>(std::distance(probs.begin(), minProbIter));
    std::size_t favoriteIdx = static_cast<std::size_t>(std::distance(probs.begin(), maxProbIter));

    std::cout << "\n=== RISK METRICS ===\n";
    std::cout << "Worst case payout (underdog wins, stake 100): "
              << std::floor((1.0 / probs[underdogIdx]) * (1.0 - cfg.houseMargin) * 100.0) << '\n';
    std::cout << "Favorite payout (stake 100): "
              << std::floor((1.0 / probs[favoriteIdx]) * (1.0 - cfg.houseMargin) * 100.0) << '\n';

    std::cout << "\n=== KELLY CRITERION (perfect knowledge) ===\n";
    for (std::size_t i = 0; i < cfg.horses.size(); ++i) {
        double b = (1.0 / probs[i]) * (1.0 - cfg.houseMargin) - 1.0;
        double p = probs[i];
        double q = 1.0 - p;
        double kelly = (b == 0.0) ? 0.0 : (p * (b + 1.0) - q) / b;
        if (kelly < 0.0) {
            kelly = 0.0;
        }
        std::cout << "  " << cfg.horses[i].name << ": " << std::fixed << std::setprecision(4)
                  << kelly * 100.0 << "% of bankroll\n";
    }

    return 0;
}

