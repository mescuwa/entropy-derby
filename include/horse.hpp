#pragma once

#include <cstdint>
#include <string>

namespace it {

struct Horse {
    std::uint32_t id;
    std::string name;
    double weight;

    Horse(std::uint32_t id_, std::string name_, double weight_)
        : id(id_), name(std::move(name_)), weight(weight_) {}
};

} // namespace it

