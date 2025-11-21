#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#include <sodium.h>

namespace it {

inline void secureZero(void* ptr, std::size_t numBytes) {
    if (ptr == nullptr || numBytes == 0) {
        return;
    }

    sodium_memzero(ptr, numBytes);
}

template <typename T>
class SecureBuffer {
public:
    using value_type = T;

    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t count) : buffer_(count) {}

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept : buffer_(std::move(other.buffer_)) {
        other.buffer_.clear();
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            secureZero(buffer_);
            buffer_ = std::move(other.buffer_);
            other.buffer_.clear();
        }
        return *this;
    }

    ~SecureBuffer() {
        secureZero(buffer_);
    }

    void resize(std::size_t count) { buffer_.resize(count); }
    std::size_t size() const { return buffer_.size(); }
    bool empty() const { return buffer_.empty(); }

    T* data() { return buffer_.data(); }
    const T* data() const { return buffer_.data(); }

    T& operator[](std::size_t idx) { return buffer_[idx]; }
    const T& operator[](std::size_t idx) const { return buffer_[idx]; }

    std::vector<T>& raw() { return buffer_; }
    const std::vector<T>& raw() const { return buffer_; }

private:
    void secureZero(std::vector<T>& data) {
        if (!data.empty()) {
            it::secureZero(static_cast<void*>(data.data()), sizeof(T) * data.size());
        }
    }

    std::vector<T> buffer_;
};

} // namespace it

