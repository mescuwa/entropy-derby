#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace it {

std::vector<std::uint8_t> secureRandomBytes(std::size_t numBytes);
std::string secureRandomHex(std::size_t numBytes);

} // namespace it


