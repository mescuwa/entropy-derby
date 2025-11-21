#pragma once

#include <boost/multiprecision/cpp_dec_float.hpp>

namespace it {

class RandomSource;

class DeterministicMath {
public:
    using HighPrecision = boost::multiprecision::cpp_dec_float_50;

    static double gaussianSample(RandomSource& rng);
    static double sqrt(double value);

private:
    static double gaussianSample(double u1, double u2);
    static HighPrecision clampUnitInterval(HighPrecision value);
};

} // namespace it


