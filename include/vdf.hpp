#pragma once

#include <cstdint>
#include <string>

namespace it {

// Public constants so configuration code can enforce safe bounds.
constexpr std::uint32_t kMinWesolowskiIterations = 50'000;
constexpr std::uint32_t kMaxWesolowskiIterations = 20'000'000;
constexpr std::uint32_t kDefaultWesolowskiIterations = 5'000'000;

struct VdfResult {
    std::string outputHex;
    std::string proofHex;
    std::uint64_t iterations = 0;
};

class WesolowskiVdf {
public:
    explicit WesolowskiVdf(std::uint64_t iterations);

    VdfResult evaluate(const std::string& input) const;
    bool verify(const std::string& input, const VdfResult& result) const;

private:
    std::uint64_t iterations_;
};

} // namespace it
