#pragma once

#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace it {

// Deterministic fixed-point math for cross-platform reproducibility.
class Fixed64 {
public:
    static constexpr std::int64_t kScale = 1'000'000; // microunits
    static constexpr std::int64_t kMaxWhole =
        std::numeric_limits<std::int64_t>::max() / kScale;
    static constexpr std::int64_t kMinWhole =
        std::numeric_limits<std::int64_t>::min() / kScale;

    Fixed64() : raw_(0) {}
    explicit Fixed64(std::int64_t whole) : raw_(scaleWhole(whole)) {}
    static Fixed64 fromRaw(std::int64_t raw) { return Fixed64(raw, RawTag{}); }
    static Fixed64 fromDouble(double value) {
        double scaled = std::round(value * static_cast<double>(kScale));
        if (scaled > static_cast<double>(std::numeric_limits<std::int64_t>::max())) {
            return Fixed64(std::numeric_limits<std::int64_t>::max(), RawTag{});
        }
        if (scaled < static_cast<double>(std::numeric_limits<std::int64_t>::min())) {
            return Fixed64(std::numeric_limits<std::int64_t>::min(), RawTag{});
        }
        return Fixed64(static_cast<std::int64_t>(scaled), RawTag{});
    }

    double toDouble() const { return static_cast<double>(raw_) / static_cast<double>(kScale); }
    std::int64_t raw() const { return raw_; }

    Fixed64 operator+(Fixed64 other) const {
        __int128 wide = static_cast<__int128>(raw_) + static_cast<__int128>(other.raw_);
        return Fixed64(clampToInt64(wide), RawTag{});
    }
    Fixed64 operator-(Fixed64 other) const {
        __int128 wide = static_cast<__int128>(raw_) - static_cast<__int128>(other.raw_);
        return Fixed64(clampToInt64(wide), RawTag{});
    }

    Fixed64 operator*(Fixed64 other) const {
        __int128 wide = static_cast<__int128>(raw_) * static_cast<__int128>(other.raw_);
        wide /= kScale;
        if (wide > std::numeric_limits<std::int64_t>::max()) {
            return Fixed64(std::numeric_limits<std::int64_t>::max(), RawTag{});
        }
        if (wide < std::numeric_limits<std::int64_t>::min()) {
            return Fixed64(std::numeric_limits<std::int64_t>::min(), RawTag{});
        }
        return Fixed64(static_cast<std::int64_t>(wide), RawTag{});
    }

    Fixed64 operator/(Fixed64 other) const {
        if (other.raw_ == 0) {
            return Fixed64(0, RawTag{});
        }
        __int128 wide = static_cast<__int128>(raw_) * static_cast<__int128>(kScale);
        wide /= other.raw_;
        if (wide > std::numeric_limits<std::int64_t>::max()) {
            return Fixed64(std::numeric_limits<std::int64_t>::max(), RawTag{});
        }
        if (wide < std::numeric_limits<std::int64_t>::min()) {
            return Fixed64(std::numeric_limits<std::int64_t>::min(), RawTag{});
        }
        return Fixed64(static_cast<std::int64_t>(wide), RawTag{});
    }

    Fixed64& operator+=(Fixed64 other) {
        __int128 wide = static_cast<__int128>(raw_) + static_cast<__int128>(other.raw_);
        raw_ = clampToInt64(wide);
        return *this;
    }

    Fixed64& operator-=(Fixed64 other) {
        __int128 wide = static_cast<__int128>(raw_) - static_cast<__int128>(other.raw_);
        raw_ = clampToInt64(wide);
        return *this;
    }

    Fixed64& operator*=(Fixed64 other) {
        *this = *this * other;
        return *this;
    }

    Fixed64& operator/=(Fixed64 other) {
        *this = *this / other;
        return *this;
    }

    bool operator<(Fixed64 other) const { return raw_ < other.raw_; }
    bool operator>(Fixed64 other) const { return raw_ > other.raw_; }
    bool operator<=(Fixed64 other) const { return raw_ <= other.raw_; }
    bool operator>=(Fixed64 other) const { return raw_ >= other.raw_; }
    bool operator==(Fixed64 other) const { return raw_ == other.raw_; }
    bool operator!=(Fixed64 other) const { return raw_ != other.raw_; }

private:
    struct RawTag {};
    explicit Fixed64(std::int64_t raw, RawTag) : raw_(raw) {}
    static std::int64_t clampToInt64(__int128 value) {
        if (value > static_cast<__int128>(std::numeric_limits<std::int64_t>::max())) {
            return std::numeric_limits<std::int64_t>::max();
        }
        if (value < static_cast<__int128>(std::numeric_limits<std::int64_t>::min())) {
            return std::numeric_limits<std::int64_t>::min();
        }
        return static_cast<std::int64_t>(value);
    }

    static std::int64_t scaleWhole(std::int64_t whole) {
        if (whole > kMaxWhole || whole < kMinWhole) {
            throw std::overflow_error("Fixed64 whole value out of range");
        }
        __int128 wide = static_cast<__int128>(whole) * static_cast<__int128>(kScale);
        return static_cast<std::int64_t>(wide);
    }

    std::int64_t raw_;
};

} // namespace it

