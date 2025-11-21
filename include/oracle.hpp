#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace it {

struct OracleObservation {
    std::uint32_t winningId = 0;
    std::string evidence;
    std::string signature;
};

class OracleBackend {
public:
    virtual ~OracleBackend() = default;
    virtual OracleObservation fetchObservation(const std::string& marketId) = 0;
};

using OraclePtr = std::shared_ptr<OracleBackend>;

} // namespace it

