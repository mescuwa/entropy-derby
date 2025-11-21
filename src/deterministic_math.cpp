#include "deterministic_math.hpp"

#include "rng.hpp"

#include <algorithm>
#include <stdexcept>

#include <boost/math/constants/constants.hpp>

namespace it {
namespace {

constexpr double kEpsilon = 1e-12;

} // namespace

DeterministicMath::HighPrecision DeterministicMath::clampUnitInterval(HighPrecision value) {
    HighPrecision min = HighPrecision(kEpsilon);
    HighPrecision max = HighPrecision(1.0 - kEpsilon);
    if (value < min) {
        return min;
    }
    if (value > max) {
        return max;
    }
    return value;
}

double DeterministicMath::gaussianSample(RandomSource& rng) {
    double u1 = rng.uniform01();
    double u2 = rng.uniform01();
    return gaussianSample(u1, u2);
}

double DeterministicMath::gaussianSample(double u1, double u2) {
    HighPrecision hpU1 = clampUnitInterval(HighPrecision(u1));
    HighPrecision hpU2 = HighPrecision(u2);

    HighPrecision magnitude =
        boost::multiprecision::sqrt(HighPrecision(-2.0) * boost::multiprecision::log(hpU1));
    HighPrecision angle =
        HighPrecision(2.0) * boost::math::constants::pi<HighPrecision>() * hpU2;
    HighPrecision result = magnitude * boost::multiprecision::cos(angle);
    return static_cast<double>(result);
}

double DeterministicMath::sqrt(double value) {
    if (value < 0.0) {
        throw std::domain_error("Cannot compute deterministic square root of negative number");
    }
    HighPrecision hpValue = HighPrecision(value);
    if (hpValue == HighPrecision(0)) {
        return 0.0;
    }
    HighPrecision root = boost::multiprecision::sqrt(hpValue);
    return static_cast<double>(root);
}

} // namespace it


