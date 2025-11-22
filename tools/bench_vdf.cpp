#include "vdf.hpp"

#include <chrono>
#include <iostream>
#include <vector>

#ifdef IT_ENABLE_GMP_BENCH
#include <gmpxx.h>
#endif

namespace {

using clock = std::chrono::steady_clock;

#ifdef IT_ENABLE_GMP_BENCH
std::string benchGmp(std::uint64_t iterations, const std::string& input) {
    const char* modulusHex =
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    mpz_class mod(modulusHex, 16);
    mpz_class base(0);
    for (unsigned char c : input) {
        base = (base * 257 + c) % mod;
    }
    mpz_class y = base;
    for (std::uint64_t i = 0; i < iterations; ++i) {
        y = (y * y) % mod;
    }
    std::ostringstream oss;
    oss << std::hex << y;
    return oss.str();
}
#endif

} // namespace

int main() {
    using namespace std::chrono_literals;

    std::vector<std::uint64_t> difficulties = {
        100'000,
        1'000'000,
        3'000'000,
        it::kDefaultWesolowskiIterations,
    };
    const std::string payload = "bench-vdf-payload";

    for (auto diff : difficulties) {
        it::WesolowskiVdf vdf(diff);
        auto start = clock::now();
        auto result = vdf.evaluate(payload);
        auto mid = clock::now();
        bool ok = vdf.verify(payload, result);
        auto end = clock::now();

        auto proveMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
        auto verifyMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

        std::cout << "Boost prover (iter=" << diff << ") time: " << proveMs
                  << "ms verify: " << verifyMs << "ms ok=" << std::boolalpha << ok << "\n";

#ifdef IT_ENABLE_GMP_BENCH
        auto gmpStart = clock::now();
        auto gmpOut = benchGmp(diff, payload);
        auto gmpEnd = clock::now();
        auto gmpMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(gmpEnd - gmpStart).count();
        std::cout << "GMP baseline (iter=" << diff << ") time: " << gmpMs
                  << "ms outputHex[8]=" << gmpOut.substr(0, 8) << "\n";
#endif
    }

    return 0;
}
