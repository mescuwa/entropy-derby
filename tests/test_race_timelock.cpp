#include "race_timelock.hpp"
#include "timelock_encryption.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

[[noreturn]] void fail(const std::string& msg) {
    std::cerr << "race_timelock_test failure: " << msg << std::endl;
    std::exit(1);
}

} // namespace

int main() {
    using namespace it;

    const std::string contextLabel = "test-race:mainnet:seed-12345";
    const std::uint64_t vdfIterations = 50'000; // Fast path for CI

    TimeLockEncryptor encryptor(vdfIterations);
    encryptor.initializeRace(contextLabel);

    RaceLevelTimeLockParams params = encryptor.getRaceParams();
    if (params.vdfOutputHex.empty() || params.vdfProofHex.empty()) {
        fail("race params missing VDF output/proof");
    }

    std::vector<std::string> plaintexts{
        "horse=1:stake=100:user=a",
        "horse=2:stake=110:user=b",
        "horse=3:stake=120:user=c",
    };

    std::vector<TimeLockedCiphertext> ciphertexts;
    ciphertexts.reserve(plaintexts.size());

    for (const auto& plain : plaintexts) {
        auto cipher = encryptor.encrypt(plain, contextLabel);
        if (cipher.puzzlePreimage != contextLabel) {
            fail("ciphertext missing race context binding");
        }
        if (cipher.puzzlePreimage == params.vdfOutputHex ||
            cipher.puzzlePreimage == params.vdfProofHex) {
            fail("ciphertext exposed VDF internals");
        }
        ciphertexts.push_back(cipher);
    }

    bool mismatchCaught = false;
    try {
        encryptor.encrypt("oops", "wrong-context");
    } catch (const std::runtime_error&) {
        mismatchCaught = true;
    }
    if (!mismatchCaught) {
        fail("context mismatch did not throw");
    }

    // Decryption must fail before the VDF is unlocked (TimeLockEncryptor path).
    TimeLockEncryptor decryptor(vdfIterations);
    decryptor.importRaceParams(params);
    if (decryptor.decrypt(ciphertexts.front())) {
        fail("decryptor succeeded before unlock");
    }

    if (!decryptor.unlockRaceKey()) {
        fail("decryptor failed to unlock race key");
    }

    for (std::size_t i = 0; i < ciphertexts.size(); ++i) {
        auto plain = decryptor.decrypt(ciphertexts[i]);
        if (!plain || *plain != plaintexts[i]) {
            fail("decryptor payload mismatch after unlock");
        }
    }

    // RaceLevelTimeLock should also refuse early decryption.
    RaceLevelTimeLock race(vdfIterations);
    race.initialize(contextLabel);
    std::string directCipher = race.encrypt("direct:bet");
    if (race.decrypt(directCipher)) {
        fail("RaceLevelTimeLock decrypted before unlock");
    }
    if (!race.unlockSecretKey()) {
        fail("RaceLevelTimeLock failed to unlock with cached VDF");
    }
    auto directPlain = race.decrypt(directCipher);
    if (!directPlain || *directPlain != "direct:bet") {
        fail("RaceLevelTimeLock failed to decrypt after unlock");
    }

    std::cout << "race_timelock_test passed" << std::endl;
    return 0;
}
