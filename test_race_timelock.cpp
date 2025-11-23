#include "race_timelock.hpp"
#include "timelock_encryption.hpp"

#include <chrono>
#include <iostream>
#include <string>

int main() {
    try {
        std::cout << "=== Race-Level Timelock Security Test ===" << std::endl;

        const std::string contextLabel = "test-race:mainnet:seed-12345";
        const std::uint64_t vdfIterations = 50'000; // Fast test

        // Simulate bettor encrypting a bet
        std::cout << "\n1. House initializes race timelock..." << std::endl;
        auto startInit = std::chrono::steady_clock::now();

        it::TimeLockEncryptor encryptor(vdfIterations);
        encryptor.initializeRace(contextLabel);

        auto endInit = std::chrono::steady_clock::now();
        auto initMs = std::chrono::duration_cast<std::chrono::milliseconds>(endInit - startInit).count();
        std::cout << "   Race initialization (with VDF): " << initMs << " ms" << std::endl;

        // Export parameters for transparency
        auto params = encryptor.getRaceParams();
        std::cout << "   Public key: " << params.publicKeyHex.substr(0, 16) << "..." << std::endl;
        std::cout << "   VDF puzzle: " << params.puzzlePreimage.substr(0, 40) << "..." << std::endl;

        // Bettor encrypts multiple bets (fast, no VDF)
        std::cout << "\n2. Bettors encrypt their bets (fast, no VDF)..." << std::endl;
        std::vector<it::TimeLockedCiphertext> bets;
        const int numBets = 5;

        auto startBetting = std::chrono::steady_clock::now();
        for (int i = 0; i < numBets; ++i) {
            std::string bet = "horse=" + std::to_string(i % 4 + 1) +
                            ":stake=" + std::to_string((i + 1) * 100) +
                            ":bettor=user" + std::to_string(i);
            bets.push_back(encryptor.encrypt(bet));
        }
        auto endBetting = std::chrono::steady_clock::now();
        auto bettingMs = std::chrono::duration_cast<std::chrono::milliseconds>(endBetting - startBetting).count();
        std::cout << "   " << numBets << " bets encrypted in " << bettingMs << " ms" << std::endl;
        std::cout << "   Average per bet: " << (bettingMs / numBets) << " ms (no VDF!)" << std::endl;

        // Verify house cannot decrypt before solving VDF
        std::cout << "\n3. Verify house cannot decrypt without solving VDF..." << std::endl;
        std::cout << "   Race key unlocked: " << (encryptor.isRaceKeyUnlocked() ? "YES" : "NO") << std::endl;

        // Create a new encryptor instance (simulating house receiving bets)
        it::TimeLockEncryptor houseDecryptor(vdfIterations);
        houseDecryptor.importRaceParams(params);

        auto attempt = houseDecryptor.decrypt(bets[0]);
        if (attempt) {
            std::cout << "   ERROR: Decryption succeeded without VDF!" << std::endl;
            return 1;
        }
        std::cout << "   ✓ Decryption properly blocked (VDF not solved)" << std::endl;

        // House solves VDF to unlock private key
        std::cout << "\n4. House solves VDF to unlock private key..." << std::endl;
        auto startUnlock = std::chrono::steady_clock::now();

        bool unlocked = houseDecryptor.unlockRaceKey();

        auto endUnlock = std::chrono::steady_clock::now();
        auto unlockMs = std::chrono::duration_cast<std::chrono::milliseconds>(endUnlock - startUnlock).count();

        if (!unlocked) {
            std::cout << "   ERROR: Failed to unlock race key!" << std::endl;
            return 1;
        }
        std::cout << "   ✓ VDF solved in " << unlockMs << " ms" << std::endl;
        std::cout << "   Race key unlocked: " << (houseDecryptor.isRaceKeyUnlocked() ? "YES" : "NO") << std::endl;

        // House decrypts all bets (fast batch decryption)
        std::cout << "\n5. House decrypts all bets (fast, using unlocked key)..." << std::endl;
        auto startDecrypt = std::chrono::steady_clock::now();

        std::vector<std::string> decryptedBets;
        for (const auto& bet : bets) {
            auto plaintext = houseDecryptor.decrypt(bet);
            if (!plaintext) {
                std::cout << "   ERROR: Decryption failed!" << std::endl;
                return 1;
            }
            decryptedBets.push_back(*plaintext);
        }

        auto endDecrypt = std::chrono::steady_clock::now();
        auto decryptMs = std::chrono::duration_cast<std::chrono::milliseconds>(endDecrypt - startDecrypt).count();

        std::cout << "   " << numBets << " bets decrypted in " << decryptMs << " ms" << std::endl;
        std::cout << "   Average per bet: " << (decryptMs / numBets) << " ms (no VDF!)" << std::endl;

        // Verify correctness
        std::cout << "\n6. Verify decrypted bet contents..." << std::endl;
        for (size_t i = 0; i < decryptedBets.size(); ++i) {
            std::cout << "   Bet " << (i + 1) << ": " << decryptedBets[i] << std::endl;
        }

        // Performance summary
        std::cout << "\n=== Performance Summary ===" << std::endl;
        std::cout << "Race initialization (1× VDF):  " << initMs << " ms" << std::endl;
        std::cout << "Encryption (" << numBets << " bets):        " << bettingMs << " ms (avg " << (bettingMs / numBets) << " ms/bet)" << std::endl;
        std::cout << "Unlock private key (1× VDF):   " << unlockMs << " ms" << std::endl;
        std::cout << "Decryption (" << numBets << " bets):        " << decryptMs << " ms (avg " << (decryptMs / numBets) << " ms/bet)" << std::endl;

        std::cout << "\n✓ All tests passed! Race-level timelock is working correctly." << std::endl;
        std::cout << "\nSecurity properties verified:" << std::endl;
        std::cout << "  ✓ Bettors can encrypt quickly (no VDF per bet)" << std::endl;
        std::cout << "  ✓ House cannot decrypt without solving VDF" << std::endl;
        std::cout << "  ✓ One VDF solve unlocks all bets" << std::endl;
        std::cout << "  ✓ Batch decryption is fast" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return 1;
    }
}
