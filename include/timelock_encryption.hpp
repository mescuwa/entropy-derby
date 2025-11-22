#pragma once

#include "vdf.hpp"

#include <optional>
#include <string>
#include <vector>

namespace it {

struct TimeLockedCiphertext {
    std::string puzzlePreimage;
    std::uint64_t iterations = 0;
    std::string ciphertextHex;
    std::string nonceHex;
};

class TimeLockEncryptor {
public:
    explicit TimeLockEncryptor(std::uint64_t iterations);

    TimeLockedCiphertext encrypt(const std::string& plaintext,
                                 const std::string& contextLabel = "bet");

    std::optional<std::string> decrypt(const TimeLockedCiphertext& ciph) const;

private:
    std::uint64_t iterations_;

    std::vector<unsigned char> hexToBytes(const std::string& hex) const;
    std::string bytesToHex(const unsigned char* data, std::size_t len) const;
    std::string deriveKey(const std::string& preimage) const;
};

} // namespace it

