#include "secure_random.hpp"

#include "secure_memory.hpp"

#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <sodium.h>

namespace it {

std::vector<std::uint8_t> secureRandomBytes(std::size_t numBytes) {
    std::vector<std::uint8_t> buffer(numBytes);
    if (numBytes == 0) {
        return buffer;
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("Unable to initialize libsodium RNG");
    }
    randombytes_buf(buffer.data(), buffer.size());
    return buffer;
}

std::string secureRandomHex(std::size_t numBytes) {
    auto bytes = secureRandomBytes(numBytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    secureZero(bytes.data(), bytes.size());
    return oss.str();
}

} // namespace it

